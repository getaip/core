"""Regression tests for progressive restaurant-booking slot filling."""

import asyncio
import unittest
from unittest.mock import patch

from app import (
    BookingCoordinator,
    append_user_message,
    clarification_response,
    extract_explicit_customer_name,
    find_mapping,
    nested_text,
    normalize_booking_update,
    reservation_identifiers,
)


class StubCoordinator(BookingCoordinator):
    """In-memory worker used to verify request-cancellation boundaries."""

    def __init__(self) -> None:
        super().__init__(object(), object(), object())
        self.release = asyncio.Event()

    async def _run_workflow(self, request_id: str) -> dict[str, object]:
        await self.release.wait()
        return {"status": "confirmed", "request_id": request_id}


class DialogueTests(unittest.TestCase):
    """Verify that collection remains conversational and replay safe."""

    def test_name_only_keeps_scheduling_questions_first(self) -> None:
        request = {
            "raw_request": "Book a table this evening.",
            "restaurant": "AIP Bistro",
            "customer_time_zone": "Asia/Dubai",
            "customer_name": "Alex",
        }

        response = clarification_response("request-id", request)

        self.assertEqual(response["requested_fields"], ["start", "party_size"])
        self.assertEqual(len(response["questions"]), 2)
        self.assertIn("customer_name", response["captured_fields"])
        self.assertEqual(
            response["known_context"],
            {
                "restaurant_configured": True,
                "customer_time_zone_configured": True,
            },
        )

    def test_contact_is_deferred_until_schedule_is_known(self) -> None:
        request = {
            "raw_request": "Book a table this evening.",
            "restaurant": "AIP Bistro",
            "customer_time_zone": "Asia/Dubai",
            "start": "2030-01-01T19:00:00+04:00",
            "party_size": 2,
            "customer_name": "Alex",
        }

        response = clarification_response("request-id", request)

        self.assertEqual(response["requested_fields"], ["customer_email"])
        self.assertEqual(len(response["questions"]), 1)

    def test_conversation_history_preserves_initial_request_and_deduplicates(
        self,
    ) -> None:
        request = {"raw_request": "Book a table this evening."}

        append_user_message(request, "Book a table this evening.")
        append_user_message(request, "My name is Alex. Please book it.")
        append_user_message(request, "My name is Alex. Please book it.")

        self.assertEqual(request["raw_request"], "Book a table this evening.")
        self.assertEqual(
            request["conversation"],
            ["Book a table this evening.", "My name is Alex. Please book it."],
        )
        self.assertEqual(
            request["latest_user_message"], "My name is Alex. Please book it."
        )

    def test_explicit_russian_name_is_extracted_without_llm_arguments(self) -> None:
        self.assertEqual(
            extract_explicit_customer_name("Меня зовут Алекс. Забронируйте."),
            "Алекс",
        )

    def test_explicit_english_full_name_is_extracted(self) -> None:
        self.assertEqual(
            extract_explicit_customer_name("My name is Alex Morgan. Please book it."),
            "Alex Morgan",
        )

    def test_booking_instruction_is_not_accepted_as_part_of_name(self) -> None:
        self.assertIsNone(
            extract_explicit_customer_name("Меня зовут Алекс забронируйте")
        )

    def test_provider_placeholders_are_not_persisted_as_customer_facts(self) -> None:
        update = normalize_booking_update(
            {
                "raw_request": "Book a table this evening.",
                "start": "",
                "party_size": 0,
                "customer_name": "  ",
                "customer_email": "",
                "customer_phone": "",
            }
        )

        self.assertEqual(update["raw_request"], "Book a table this evening.")
        for field in (
            "start",
            "party_size",
            "customer_name",
            "customer_email",
            "customer_phone",
        ):
            self.assertIsNone(update[field])

    def test_invalid_party_size_remains_an_unanswered_slot(self) -> None:
        request = {
            "restaurant": "AIP Bistro",
            "customer_time_zone": "Asia/Dubai",
            "party_size": 0,
        }

        response = clarification_response("request-id", request)

        self.assertEqual(response["requested_fields"], ["start", "party_size"])
        self.assertNotIn("party_size", response["captured_fields"])

    def test_pending_approval_wire_shape_does_not_require_terminal_decision(
        self,
    ) -> None:
        payload = {
            "approval": {"request": {"approval_id": "appr_1"}, "status": "pending"}
        }

        record = find_mapping(payload, {"request", "status"})

        self.assertIsNotNone(record)
        self.assertEqual(record["status"], "pending")

    def test_running_action_wire_shape_does_not_require_result(self) -> None:
        payload = {"action": {"action_id": "act_1", "state": "running"}}

        record = find_mapping(payload, {"action_id", "state"})

        self.assertIsNotNone(record)
        self.assertEqual(record["state"], "running")

    def test_terminal_approval_binds_the_canonical_decision_principal(self) -> None:
        payload = {
            "request": {"id": "appr_1"},
            "status": "approved",
            "decision": {
                "decision": "approved",
                "approver": {
                    "kind": "agent",
                    "id": "agent:hermes_operator:supervisor",
                },
            },
        }

        record = find_mapping(payload, {"request", "status"})

        self.assertIsNotNone(record)
        self.assertEqual(
            nested_text(record["decision"], "approver"),
            "agent:hermes_operator:supervisor",
        )

    def test_seated_reservation_uses_the_action_bound_seat(self) -> None:
        output = {
            "data": {
                "uid": "booking-parent",
                "attendees": [
                    {
                        "seatUid": "seat-old",
                        "metadata": {"aip_action_id": "act-old"},
                    },
                    {
                        "seatUid": "seat-current",
                        "metadata": {"aip_action_id": "act-current"},
                    },
                ],
            }
        }

        self.assertEqual(
            reservation_identifiers(output, "act-current"),
            ("booking-parent", "seat-current"),
        )


class BackgroundWorkflowTests(unittest.IsolatedAsyncioTestCase):
    """Verify that customer request lifetimes do not own durable execution."""

    async def test_cancelling_waiter_does_not_cancel_workflow(self) -> None:
        coordinator = StubCoordinator()
        task = await coordinator._ensure_execution("request-1")
        waiter = asyncio.create_task(coordinator._wait_for_execution("request-1", task))
        await asyncio.sleep(0)

        waiter.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await waiter

        self.assertFalse(task.cancelled())
        coordinator.release.set()
        self.assertEqual((await task)["status"], "confirmed")

    async def test_bounded_wait_returns_processing_while_worker_continues(self) -> None:
        coordinator = StubCoordinator()
        task = await coordinator._ensure_execution("request-2")

        with patch("app.PUBLIC_WAIT_SECONDS", 0.001):
            response = await coordinator._wait_for_execution("request-2", task)

        self.assertEqual(response["status"], "processing")
        self.assertFalse(task.done())
        await coordinator.close()


if __name__ == "__main__":
    unittest.main()
