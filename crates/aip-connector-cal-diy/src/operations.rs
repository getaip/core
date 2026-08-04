//! Version-pinned Cal.diy API v2 operation catalogue.

use aip_core::RiskLevel;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

/// Connector-selected version accepted by Cal.diy all-version controllers.
pub const GENERAL_API_VERSION: &str = "2024-08-13";
/// Cal.diy API version used by booking operations.
pub const BOOKINGS_API_VERSION: &str = GENERAL_API_VERSION;
/// Cal.diy API version used by slot operations.
pub const SLOTS_API_VERSION: &str = "2024-09-04";
/// Cal.diy API version used by event-type operations.
pub const EVENT_TYPES_API_VERSION: &str = "2024-06-14";
/// Cal.diy default API version used by unversioned private-link routes.
pub const PRIVATE_LINKS_API_VERSION: &str = "2024-04-15";
/// Cal.diy API version used by schedule operations.
pub const SCHEDULES_API_VERSION: &str = "2024-06-11";

/// Webhook triggers implemented by the pinned Cal.diy revision.
pub const WEBHOOK_TRIGGERS: &[&str] = &[
    "BOOKING_CREATED",
    "BOOKING_PAYMENT_INITIATED",
    "BOOKING_PAID",
    "BOOKING_RESCHEDULED",
    "BOOKING_REQUESTED",
    "BOOKING_CANCELLED",
    "BOOKING_REJECTED",
    "BOOKING_NO_SHOW_UPDATED",
    "FORM_SUBMITTED",
    "MEETING_ENDED",
    "MEETING_STARTED",
    "RECORDING_READY",
    "RECORDING_TRANSCRIPTION_GENERATED",
    "OOO_CREATED",
    "AFTER_HOSTS_CAL_VIDEO_NO_SHOW",
    "AFTER_GUESTS_CAL_VIDEO_NO_SHOW",
    "FORM_SUBMITTED_NO_EVENT",
    "DELEGATION_CREDENTIAL_ERROR",
    "WRONG_ASSIGNMENT_REPORT",
];

const CAL_DIY_LOCALES: &[&str] = &[
    "ar", "ca", "de", "es", "eu", "he", "id", "ja", "lv", "pl", "ro", "sr", "th", "vi", "az", "cs",
    "el", "es-419", "fi", "hr", "it", "km", "nl", "pt", "ru", "sv", "tr", "zh-CN", "bg", "da",
    "en", "et", "fr", "hu", "iw", "ko", "no", "pt-BR", "sk", "ta", "uk", "zh-TW", "bn",
];

const WEEK_DAYS: &[&str] = &[
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
];

const EVENT_TYPE_INTERFACE_LANGUAGES: &[&str] = &[
    "", "en", "ar", "az", "bg", "bn", "ca", "cs", "da", "de", "el", "es", "es-419", "eu", "et",
    "fi", "fr", "he", "hu", "it", "ja", "km", "ko", "nl", "no", "pl", "pt-BR", "pt", "ro", "ru",
    "sk-SK", "sr", "sv", "tr", "uk", "vi", "zh-CN", "zh-TW",
];

/// HTTP verb used by one Cal.diy operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CalDiyHttpMethod {
    /// HTTP GET.
    Get,
    /// HTTP POST.
    Post,
    /// HTTP PATCH.
    Patch,
    /// HTTP PUT.
    Put,
    /// HTTP DELETE.
    Delete,
}

/// Stable scheduling operations exposed by the connector.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalDiyOperation {
    /// Read the authenticated profile.
    ProfileGet,
    /// Update the authenticated profile.
    ProfileUpdate,
    /// List event types.
    EventTypeList,
    /// Read an event type.
    EventTypeGet,
    /// Create an event type.
    EventTypeCreate,
    /// Update an event type.
    EventTypeUpdate,
    /// Delete an event type.
    EventTypeDelete,
    /// List private links for an event type.
    EventTypePrivateLinkList,
    /// Create a private link for an event type.
    EventTypePrivateLinkCreate,
    /// Update an event-type private link.
    EventTypePrivateLinkUpdate,
    /// Delete an event-type private link.
    EventTypePrivateLinkDelete,
    /// List event-type webhooks.
    EventTypeWebhookList,
    /// Read an event-type webhook.
    EventTypeWebhookGet,
    /// Create an event-type webhook.
    EventTypeWebhookCreate,
    /// Update an event-type webhook.
    EventTypeWebhookUpdate,
    /// Delete an event-type webhook.
    EventTypeWebhookDelete,
    /// Delete all webhooks for an event type.
    EventTypeWebhookDeleteAll,
    /// List available slots.
    SlotList,
    /// Reserve a slot.
    SlotReservationCreate,
    /// Read a slot reservation.
    SlotReservationGet,
    /// Update a slot reservation.
    SlotReservationUpdate,
    /// Release a slot reservation.
    SlotReservationDelete,
    /// List bookings.
    BookingList,
    /// Read a booking.
    BookingGet,
    /// Read a seated booking by its seat uid.
    BookingGetBySeat,
    /// Create a booking.
    BookingCreate,
    /// Reschedule a booking.
    BookingReschedule,
    /// Cancel a booking.
    BookingCancel,
    /// Confirm a pending booking.
    BookingConfirm,
    /// Decline a pending booking.
    BookingDecline,
    /// Mark booking attendees absent or present.
    BookingMarkAbsent,
    /// Reassign a round-robin booking automatically.
    BookingReassign,
    /// Reassign a round-robin booking to one user.
    BookingReassignToUser,
    /// Update a booking location.
    BookingLocationUpdate,
    /// List booking attendees.
    BookingAttendeeList,
    /// Read one booking attendee.
    BookingAttendeeGet,
    /// Add a booking attendee.
    BookingAttendeeAdd,
    /// Remove a booking attendee.
    BookingAttendeeDelete,
    /// Add guests to a booking.
    BookingGuestAdd,
    /// Read booking calendar links.
    BookingCalendarLinksGet,
    /// List booking calendar references.
    BookingReferenceList,
    /// List booking recordings.
    BookingRecordingList,
    /// List booking transcript links.
    BookingTranscriptList,
    /// List booking conferencing sessions.
    BookingConferencingSessionList,
    /// List connected calendars.
    CalendarList,
    /// Check whether an authenticated calendar provider is connected.
    CalendarProviderCheck,
    /// Disconnect one authenticated calendar credential.
    CalendarDisconnect,
    /// Check the authenticated user's ICS feed connection.
    CalendarIcsFeedCheck,
    /// Read busy times across selected calendars.
    CalendarBusyTimeList,
    /// List unified calendar connections.
    CalendarConnectionList,
    /// List events for one unified calendar connection.
    CalendarConnectionEventList,
    /// Read one event for a unified calendar connection.
    CalendarConnectionEventGet,
    /// Create one event for a unified calendar connection.
    CalendarConnectionEventCreate,
    /// Update one event for a unified calendar connection.
    CalendarConnectionEventUpdate,
    /// Delete one event for a unified calendar connection.
    CalendarConnectionEventDelete,
    /// Read free/busy for one unified calendar connection.
    CalendarConnectionFreeBusyGet,
    /// List calendar events.
    CalendarEventList,
    /// Read one calendar event.
    CalendarEventGet,
    /// Create one calendar event.
    CalendarEventCreate,
    /// Update one calendar event.
    CalendarEventUpdate,
    /// Delete one calendar event.
    CalendarEventDelete,
    /// Read free/busy for one calendar provider.
    CalendarFreeBusyGet,
    /// Update the user's destination calendar.
    DestinationCalendarUpdate,
    /// Add a selected conflict calendar.
    SelectedCalendarAdd,
    /// Remove a selected conflict calendar.
    SelectedCalendarDelete,
    /// List installed conferencing applications.
    ConferencingList,
    /// Read the default conferencing application.
    ConferencingDefaultGet,
    /// Set the default conferencing application.
    ConferencingDefaultSet,
    /// Connect a non-OAuth conferencing application.
    ConferencingConnect,
    /// Disconnect a conferencing application.
    ConferencingDisconnect,
    /// List schedules.
    ScheduleList,
    /// Read the default schedule.
    ScheduleDefaultGet,
    /// Read one schedule.
    ScheduleGet,
    /// Create a schedule.
    ScheduleCreate,
    /// Update a schedule.
    ScheduleUpdate,
    /// Delete a schedule.
    ScheduleDelete,
    /// List user webhooks.
    WebhookList,
    /// Read a user webhook.
    WebhookGet,
    /// Create a user webhook.
    WebhookCreate,
    /// Update a user webhook.
    WebhookUpdate,
    /// Delete a user webhook.
    WebhookDelete,
}

/// Complete stable operation set published by the connector.
pub const ALL_OPERATIONS: &[CalDiyOperation] = &[
    CalDiyOperation::ProfileGet,
    CalDiyOperation::ProfileUpdate,
    CalDiyOperation::EventTypeList,
    CalDiyOperation::EventTypeGet,
    CalDiyOperation::EventTypeCreate,
    CalDiyOperation::EventTypeUpdate,
    CalDiyOperation::EventTypeDelete,
    CalDiyOperation::EventTypePrivateLinkList,
    CalDiyOperation::EventTypePrivateLinkCreate,
    CalDiyOperation::EventTypePrivateLinkUpdate,
    CalDiyOperation::EventTypePrivateLinkDelete,
    CalDiyOperation::EventTypeWebhookList,
    CalDiyOperation::EventTypeWebhookGet,
    CalDiyOperation::EventTypeWebhookCreate,
    CalDiyOperation::EventTypeWebhookUpdate,
    CalDiyOperation::EventTypeWebhookDelete,
    CalDiyOperation::EventTypeWebhookDeleteAll,
    CalDiyOperation::SlotList,
    CalDiyOperation::SlotReservationCreate,
    CalDiyOperation::SlotReservationGet,
    CalDiyOperation::SlotReservationUpdate,
    CalDiyOperation::SlotReservationDelete,
    CalDiyOperation::BookingList,
    CalDiyOperation::BookingGet,
    CalDiyOperation::BookingGetBySeat,
    CalDiyOperation::BookingCreate,
    CalDiyOperation::BookingReschedule,
    CalDiyOperation::BookingCancel,
    CalDiyOperation::BookingConfirm,
    CalDiyOperation::BookingDecline,
    CalDiyOperation::BookingMarkAbsent,
    CalDiyOperation::BookingReassign,
    CalDiyOperation::BookingReassignToUser,
    CalDiyOperation::BookingLocationUpdate,
    CalDiyOperation::BookingAttendeeList,
    CalDiyOperation::BookingAttendeeGet,
    CalDiyOperation::BookingAttendeeAdd,
    CalDiyOperation::BookingAttendeeDelete,
    CalDiyOperation::BookingGuestAdd,
    CalDiyOperation::BookingCalendarLinksGet,
    CalDiyOperation::BookingReferenceList,
    CalDiyOperation::BookingRecordingList,
    CalDiyOperation::BookingTranscriptList,
    CalDiyOperation::BookingConferencingSessionList,
    CalDiyOperation::CalendarList,
    CalDiyOperation::CalendarProviderCheck,
    CalDiyOperation::CalendarDisconnect,
    CalDiyOperation::CalendarIcsFeedCheck,
    CalDiyOperation::CalendarBusyTimeList,
    CalDiyOperation::CalendarConnectionList,
    CalDiyOperation::CalendarConnectionEventList,
    CalDiyOperation::CalendarConnectionEventGet,
    CalDiyOperation::CalendarConnectionEventCreate,
    CalDiyOperation::CalendarConnectionEventUpdate,
    CalDiyOperation::CalendarConnectionEventDelete,
    CalDiyOperation::CalendarConnectionFreeBusyGet,
    CalDiyOperation::CalendarEventList,
    CalDiyOperation::CalendarEventGet,
    CalDiyOperation::CalendarEventCreate,
    CalDiyOperation::CalendarEventUpdate,
    CalDiyOperation::CalendarEventDelete,
    CalDiyOperation::CalendarFreeBusyGet,
    CalDiyOperation::DestinationCalendarUpdate,
    CalDiyOperation::SelectedCalendarAdd,
    CalDiyOperation::SelectedCalendarDelete,
    CalDiyOperation::ConferencingList,
    CalDiyOperation::ConferencingDefaultGet,
    CalDiyOperation::ConferencingDefaultSet,
    CalDiyOperation::ConferencingConnect,
    CalDiyOperation::ConferencingDisconnect,
    CalDiyOperation::ScheduleList,
    CalDiyOperation::ScheduleDefaultGet,
    CalDiyOperation::ScheduleGet,
    CalDiyOperation::ScheduleCreate,
    CalDiyOperation::ScheduleUpdate,
    CalDiyOperation::ScheduleDelete,
    CalDiyOperation::WebhookList,
    CalDiyOperation::WebhookGet,
    CalDiyOperation::WebhookCreate,
    CalDiyOperation::WebhookUpdate,
    CalDiyOperation::WebhookDelete,
];

/// Upstream OpenAPI routes intentionally kept in the operator control plane.
///
/// These endpoints provision or rotate credentials, establish browser OAuth
/// sessions, administer OAuth clients, or verify ownership of email/phone
/// resources. Publishing them as agent-callable product capabilities would
/// cross the connector credential boundary. The 81 operations above are the
/// complete pinned business-operation surface; this explicit inventory keeps
/// the distinction auditable rather than silently omitting endpoints.
pub const OPERATOR_ONLY_EXCLUDED_ROUTES: &[(CalDiyHttpMethod, &str)] = &[
    (CalDiyHttpMethod::Delete, "/v2/oauth-clients/{client_id}"),
    (
        CalDiyHttpMethod::Delete,
        "/v2/oauth-clients/{client_id}/users/{user_id}",
    ),
    (
        CalDiyHttpMethod::Delete,
        "/v2/oauth-clients/{client_id}/webhooks",
    ),
    (
        CalDiyHttpMethod::Delete,
        "/v2/oauth-clients/{client_id}/webhooks/{webhook_id}",
    ),
    (CalDiyHttpMethod::Get, "/v2/auth/oauth2/clients/{client_id}"),
    (CalDiyHttpMethod::Get, "/v2/calendars/{calendar}/connect"),
    (CalDiyHttpMethod::Get, "/v2/calendars/{calendar}/save"),
    (
        CalDiyHttpMethod::Get,
        "/v2/conferencing/{app}/oauth/auth-url",
    ),
    (
        CalDiyHttpMethod::Get,
        "/v2/conferencing/{app}/oauth/callback",
    ),
    (CalDiyHttpMethod::Get, "/v2/oauth-clients"),
    (CalDiyHttpMethod::Get, "/v2/oauth-clients/{client_id}"),
    (CalDiyHttpMethod::Get, "/v2/oauth-clients/{client_id}/users"),
    (
        CalDiyHttpMethod::Get,
        "/v2/oauth-clients/{client_id}/users/{user_id}",
    ),
    (
        CalDiyHttpMethod::Get,
        "/v2/oauth-clients/{client_id}/webhooks",
    ),
    (
        CalDiyHttpMethod::Get,
        "/v2/oauth-clients/{client_id}/webhooks/{webhook_id}",
    ),
    (CalDiyHttpMethod::Get, "/v2/stripe/check"),
    (CalDiyHttpMethod::Get, "/v2/stripe/connect"),
    (CalDiyHttpMethod::Get, "/v2/stripe/save"),
    (CalDiyHttpMethod::Get, "/v2/verified-resources/emails"),
    (
        CalDiyHttpMethod::Get,
        "/v2/verified-resources/emails/{resource_id}",
    ),
    (CalDiyHttpMethod::Get, "/v2/verified-resources/phones"),
    (
        CalDiyHttpMethod::Get,
        "/v2/verified-resources/phones/{resource_id}",
    ),
    (CalDiyHttpMethod::Patch, "/v2/oauth-clients/{client_id}"),
    (
        CalDiyHttpMethod::Patch,
        "/v2/oauth-clients/{client_id}/users/{user_id}",
    ),
    (
        CalDiyHttpMethod::Patch,
        "/v2/oauth-clients/{client_id}/webhooks/{webhook_id}",
    ),
    (CalDiyHttpMethod::Post, "/v2/api-keys/refresh"),
    (CalDiyHttpMethod::Post, "/v2/auth/oauth2/token"),
    (CalDiyHttpMethod::Post, "/v2/calendars/ics-feed/save"),
    (
        CalDiyHttpMethod::Post,
        "/v2/calendars/{calendar}/credentials",
    ),
    (CalDiyHttpMethod::Post, "/v2/oauth-clients"),
    (
        CalDiyHttpMethod::Post,
        "/v2/oauth-clients/{client_id}/users",
    ),
    (
        CalDiyHttpMethod::Post,
        "/v2/oauth-clients/{client_id}/users/{user_id}/force-refresh",
    ),
    (
        CalDiyHttpMethod::Post,
        "/v2/oauth-clients/{client_id}/webhooks",
    ),
    (CalDiyHttpMethod::Post, "/v2/oauth/{provider}/refresh"),
    (
        CalDiyHttpMethod::Post,
        "/v2/verified-resources/emails/verification-code/request",
    ),
    (
        CalDiyHttpMethod::Post,
        "/v2/verified-resources/emails/verification-code/verify",
    ),
    (
        CalDiyHttpMethod::Post,
        "/v2/verified-resources/phones/verification-code/request",
    ),
    (
        CalDiyHttpMethod::Post,
        "/v2/verified-resources/phones/verification-code/verify",
    ),
];

/// Deprecated singular calendar-event aliases omitted in favour of the
/// canonical `/events/` routes with identical provider semantics.
pub const DEPRECATED_ALIAS_EXCLUDED_ROUTES: &[(CalDiyHttpMethod, &str)] = &[
    (
        CalDiyHttpMethod::Get,
        "/v2/calendars/{calendar}/event/{event_uid}",
    ),
    (
        CalDiyHttpMethod::Patch,
        "/v2/calendars/{calendar}/event/{event_uid}",
    ),
];

impl CalDiyOperation {
    /// Stable suffix used in the AIP capability id.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::ProfileGet => "profile.get",
            Self::ProfileUpdate => "profile.update",
            Self::EventTypeList => "event_type.list",
            Self::EventTypeGet => "event_type.get",
            Self::EventTypeCreate => "event_type.create",
            Self::EventTypeUpdate => "event_type.update",
            Self::EventTypeDelete => "event_type.delete",
            Self::EventTypePrivateLinkList => "event_type.private_link.list",
            Self::EventTypePrivateLinkCreate => "event_type.private_link.create",
            Self::EventTypePrivateLinkUpdate => "event_type.private_link.update",
            Self::EventTypePrivateLinkDelete => "event_type.private_link.delete",
            Self::EventTypeWebhookList => "event_type.webhook.list",
            Self::EventTypeWebhookGet => "event_type.webhook.get",
            Self::EventTypeWebhookCreate => "event_type.webhook.create",
            Self::EventTypeWebhookUpdate => "event_type.webhook.update",
            Self::EventTypeWebhookDelete => "event_type.webhook.delete",
            Self::EventTypeWebhookDeleteAll => "event_type.webhook.delete_all",
            Self::SlotList => "slot.list",
            Self::SlotReservationCreate => "slot.reservation.create",
            Self::SlotReservationGet => "slot.reservation.get",
            Self::SlotReservationUpdate => "slot.reservation.update",
            Self::SlotReservationDelete => "slot.reservation.delete",
            Self::BookingList => "booking.list",
            Self::BookingGet => "booking.get",
            Self::BookingGetBySeat => "booking.get_by_seat",
            Self::BookingCreate => "booking.create",
            Self::BookingReschedule => "booking.reschedule",
            Self::BookingCancel => "booking.cancel",
            Self::BookingConfirm => "booking.confirm",
            Self::BookingDecline => "booking.decline",
            Self::BookingMarkAbsent => "booking.mark_absent",
            Self::BookingReassign => "booking.reassign",
            Self::BookingReassignToUser => "booking.reassign_to_user",
            Self::BookingLocationUpdate => "booking.location.update",
            Self::BookingAttendeeList => "booking.attendee.list",
            Self::BookingAttendeeGet => "booking.attendee.get",
            Self::BookingAttendeeAdd => "booking.attendee.add",
            Self::BookingAttendeeDelete => "booking.attendee.delete",
            Self::BookingGuestAdd => "booking.guest.add",
            Self::BookingCalendarLinksGet => "booking.calendar_links.get",
            Self::BookingReferenceList => "booking.reference.list",
            Self::BookingRecordingList => "booking.recording.list",
            Self::BookingTranscriptList => "booking.transcript.list",
            Self::BookingConferencingSessionList => "booking.conferencing_session.list",
            Self::CalendarList => "calendar.list",
            Self::CalendarProviderCheck => "calendar.provider.check",
            Self::CalendarDisconnect => "calendar.disconnect",
            Self::CalendarIcsFeedCheck => "calendar.ics_feed.check",
            Self::CalendarBusyTimeList => "calendar.busy_time.list",
            Self::CalendarConnectionList => "calendar.connection.list",
            Self::CalendarConnectionEventList => "calendar.connection.event.list",
            Self::CalendarConnectionEventGet => "calendar.connection.event.get",
            Self::CalendarConnectionEventCreate => "calendar.connection.event.create",
            Self::CalendarConnectionEventUpdate => "calendar.connection.event.update",
            Self::CalendarConnectionEventDelete => "calendar.connection.event.delete",
            Self::CalendarConnectionFreeBusyGet => "calendar.connection.free_busy.get",
            Self::CalendarEventList => "calendar.event.list",
            Self::CalendarEventGet => "calendar.event.get",
            Self::CalendarEventCreate => "calendar.event.create",
            Self::CalendarEventUpdate => "calendar.event.update",
            Self::CalendarEventDelete => "calendar.event.delete",
            Self::CalendarFreeBusyGet => "calendar.free_busy.get",
            Self::DestinationCalendarUpdate => "calendar.destination.update",
            Self::SelectedCalendarAdd => "calendar.selected.add",
            Self::SelectedCalendarDelete => "calendar.selected.delete",
            Self::ConferencingList => "conferencing.list",
            Self::ConferencingDefaultGet => "conferencing.default.get",
            Self::ConferencingDefaultSet => "conferencing.default.set",
            Self::ConferencingConnect => "conferencing.connect",
            Self::ConferencingDisconnect => "conferencing.disconnect",
            Self::ScheduleList => "schedule.list",
            Self::ScheduleDefaultGet => "schedule.default.get",
            Self::ScheduleGet => "schedule.get",
            Self::ScheduleCreate => "schedule.create",
            Self::ScheduleUpdate => "schedule.update",
            Self::ScheduleDelete => "schedule.delete",
            Self::WebhookList => "webhook.list",
            Self::WebhookGet => "webhook.get",
            Self::WebhookCreate => "webhook.create",
            Self::WebhookUpdate => "webhook.update",
            Self::WebhookDelete => "webhook.delete",
        }
    }

    /// Human-readable operation name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ProfileGet => "Cal.diy get profile",
            Self::ProfileUpdate => "Cal.diy update profile",
            Self::EventTypeList => "Cal.diy list event types",
            Self::EventTypeGet => "Cal.diy get event type",
            Self::EventTypeCreate => "Cal.diy create event type",
            Self::EventTypeUpdate => "Cal.diy update event type",
            Self::EventTypeDelete => "Cal.diy delete event type",
            Self::EventTypePrivateLinkList => "Cal.diy list event-type private links",
            Self::EventTypePrivateLinkCreate => "Cal.diy create event-type private link",
            Self::EventTypePrivateLinkUpdate => "Cal.diy update event-type private link",
            Self::EventTypePrivateLinkDelete => "Cal.diy delete event-type private link",
            Self::EventTypeWebhookList => "Cal.diy list event-type webhooks",
            Self::EventTypeWebhookGet => "Cal.diy get event-type webhook",
            Self::EventTypeWebhookCreate => "Cal.diy create event-type webhook",
            Self::EventTypeWebhookUpdate => "Cal.diy update event-type webhook",
            Self::EventTypeWebhookDelete => "Cal.diy delete event-type webhook",
            Self::EventTypeWebhookDeleteAll => "Cal.diy delete all event-type webhooks",
            Self::SlotList => "Cal.diy list available slots",
            Self::SlotReservationCreate => "Cal.diy reserve slot",
            Self::SlotReservationGet => "Cal.diy get slot reservation",
            Self::SlotReservationUpdate => "Cal.diy update slot reservation",
            Self::SlotReservationDelete => "Cal.diy release slot reservation",
            Self::BookingList => "Cal.diy list bookings",
            Self::BookingGet => "Cal.diy get booking",
            Self::BookingGetBySeat => "Cal.diy get booking by seat uid",
            Self::BookingCreate => "Cal.diy create booking",
            Self::BookingReschedule => "Cal.diy reschedule booking",
            Self::BookingCancel => "Cal.diy cancel booking",
            Self::BookingConfirm => "Cal.diy confirm booking",
            Self::BookingDecline => "Cal.diy decline booking",
            Self::BookingMarkAbsent => "Cal.diy mark booking attendance",
            Self::BookingReassign => "Cal.diy reassign booking",
            Self::BookingReassignToUser => "Cal.diy reassign booking to user",
            Self::BookingLocationUpdate => "Cal.diy update booking location",
            Self::BookingAttendeeList => "Cal.diy list booking attendees",
            Self::BookingAttendeeGet => "Cal.diy get booking attendee",
            Self::BookingAttendeeAdd => "Cal.diy add booking attendee",
            Self::BookingAttendeeDelete => "Cal.diy remove booking attendee",
            Self::BookingGuestAdd => "Cal.diy add booking guests",
            Self::BookingCalendarLinksGet => "Cal.diy get booking calendar links",
            Self::BookingReferenceList => "Cal.diy list booking references",
            Self::BookingRecordingList => "Cal.diy list booking recordings",
            Self::BookingTranscriptList => "Cal.diy list booking transcripts",
            Self::BookingConferencingSessionList => "Cal.diy list conferencing sessions",
            Self::CalendarList => "Cal.diy list connected calendars",
            Self::CalendarProviderCheck => "Cal.diy check calendar provider",
            Self::CalendarDisconnect => "Cal.diy disconnect calendar",
            Self::CalendarIcsFeedCheck => "Cal.diy check ICS feed",
            Self::CalendarBusyTimeList => "Cal.diy list calendar busy times",
            Self::CalendarConnectionList => "Cal.diy list calendar connections",
            Self::CalendarConnectionEventList => "Cal.diy list connection calendar events",
            Self::CalendarConnectionEventGet => "Cal.diy get connection calendar event",
            Self::CalendarConnectionEventCreate => "Cal.diy create connection calendar event",
            Self::CalendarConnectionEventUpdate => "Cal.diy update connection calendar event",
            Self::CalendarConnectionEventDelete => "Cal.diy delete connection calendar event",
            Self::CalendarConnectionFreeBusyGet => "Cal.diy get connection free busy",
            Self::CalendarEventList => "Cal.diy list calendar events",
            Self::CalendarEventGet => "Cal.diy get calendar event",
            Self::CalendarEventCreate => "Cal.diy create calendar event",
            Self::CalendarEventUpdate => "Cal.diy update calendar event",
            Self::CalendarEventDelete => "Cal.diy delete calendar event",
            Self::CalendarFreeBusyGet => "Cal.diy get calendar free busy",
            Self::DestinationCalendarUpdate => "Cal.diy update destination calendar",
            Self::SelectedCalendarAdd => "Cal.diy add selected calendar",
            Self::SelectedCalendarDelete => "Cal.diy remove selected calendar",
            Self::ConferencingList => "Cal.diy list conferencing apps",
            Self::ConferencingDefaultGet => "Cal.diy get default conferencing app",
            Self::ConferencingDefaultSet => "Cal.diy set default conferencing app",
            Self::ConferencingConnect => "Cal.diy connect conferencing app",
            Self::ConferencingDisconnect => "Cal.diy disconnect conferencing app",
            Self::ScheduleList => "Cal.diy list schedules",
            Self::ScheduleDefaultGet => "Cal.diy get default schedule",
            Self::ScheduleGet => "Cal.diy get schedule",
            Self::ScheduleCreate => "Cal.diy create schedule",
            Self::ScheduleUpdate => "Cal.diy update schedule",
            Self::ScheduleDelete => "Cal.diy delete schedule",
            Self::WebhookList => "Cal.diy list webhooks",
            Self::WebhookGet => "Cal.diy get webhook",
            Self::WebhookCreate => "Cal.diy create webhook",
            Self::WebhookUpdate => "Cal.diy update webhook",
            Self::WebhookDelete => "Cal.diy delete webhook",
        }
    }

    /// Provider route template.
    #[must_use]
    pub const fn path_template(self) -> &'static str {
        match self {
            Self::ProfileGet | Self::ProfileUpdate => "/v2/me",
            Self::EventTypeList | Self::EventTypeCreate => "/v2/event-types",
            Self::EventTypeGet | Self::EventTypeUpdate | Self::EventTypeDelete => {
                "/v2/event-types/{event_type_id}"
            }
            Self::EventTypePrivateLinkList | Self::EventTypePrivateLinkCreate => {
                "/v2/event-types/{event_type_id}/private-links"
            }
            Self::EventTypePrivateLinkUpdate | Self::EventTypePrivateLinkDelete => {
                "/v2/event-types/{event_type_id}/private-links/{link_id}"
            }
            Self::EventTypeWebhookList
            | Self::EventTypeWebhookCreate
            | Self::EventTypeWebhookDeleteAll => "/v2/event-types/{event_type_id}/webhooks",
            Self::EventTypeWebhookGet
            | Self::EventTypeWebhookUpdate
            | Self::EventTypeWebhookDelete => {
                "/v2/event-types/{event_type_id}/webhooks/{webhook_id}"
            }
            Self::SlotList => "/v2/slots",
            Self::SlotReservationCreate => "/v2/slots/reservations",
            Self::SlotReservationGet
            | Self::SlotReservationUpdate
            | Self::SlotReservationDelete => "/v2/slots/reservations/{reservation_uid}",
            Self::BookingList | Self::BookingCreate => "/v2/bookings",
            Self::BookingGet => "/v2/bookings/{booking_uid}",
            Self::BookingGetBySeat => "/v2/bookings/by-seat/{seat_uid}",
            Self::BookingReschedule => "/v2/bookings/{booking_uid}/reschedule",
            Self::BookingCancel => "/v2/bookings/{booking_uid}/cancel",
            Self::BookingConfirm => "/v2/bookings/{booking_uid}/confirm",
            Self::BookingDecline => "/v2/bookings/{booking_uid}/decline",
            Self::BookingMarkAbsent => "/v2/bookings/{booking_uid}/mark-absent",
            Self::BookingReassign => "/v2/bookings/{booking_uid}/reassign",
            Self::BookingReassignToUser => "/v2/bookings/{booking_uid}/reassign/{user_id}",
            Self::BookingLocationUpdate => "/v2/bookings/{booking_uid}/location",
            Self::BookingAttendeeList | Self::BookingAttendeeAdd => {
                "/v2/bookings/{booking_uid}/attendees"
            }
            Self::BookingAttendeeGet | Self::BookingAttendeeDelete => {
                "/v2/bookings/{booking_uid}/attendees/{attendee_id}"
            }
            Self::BookingGuestAdd => "/v2/bookings/{booking_uid}/guests",
            Self::BookingCalendarLinksGet => "/v2/bookings/{booking_uid}/calendar-links",
            Self::BookingReferenceList => "/v2/bookings/{booking_uid}/references",
            Self::BookingRecordingList => "/v2/bookings/{booking_uid}/recordings",
            Self::BookingTranscriptList => "/v2/bookings/{booking_uid}/transcripts",
            Self::BookingConferencingSessionList => {
                "/v2/bookings/{booking_uid}/conferencing-sessions"
            }
            Self::CalendarList => "/v2/calendars",
            Self::CalendarProviderCheck => "/v2/calendars/{calendar}/check",
            Self::CalendarDisconnect => "/v2/calendars/{calendar}/disconnect",
            Self::CalendarIcsFeedCheck => "/v2/calendars/ics-feed/check",
            Self::CalendarBusyTimeList => "/v2/calendars/busy-times",
            Self::CalendarConnectionList => "/v2/calendars/connections",
            Self::CalendarConnectionEventList | Self::CalendarConnectionEventCreate => {
                "/v2/calendars/connections/{connection_id}/events"
            }
            Self::CalendarConnectionEventGet
            | Self::CalendarConnectionEventUpdate
            | Self::CalendarConnectionEventDelete => {
                "/v2/calendars/connections/{connection_id}/events/{event_id}"
            }
            Self::CalendarConnectionFreeBusyGet => {
                "/v2/calendars/connections/{connection_id}/freebusy"
            }
            Self::CalendarEventList | Self::CalendarEventCreate => {
                "/v2/calendars/{calendar}/events"
            }
            Self::CalendarEventGet | Self::CalendarEventUpdate | Self::CalendarEventDelete => {
                "/v2/calendars/{calendar}/events/{event_uid}"
            }
            Self::CalendarFreeBusyGet => "/v2/calendars/{calendar}/freebusy",
            Self::DestinationCalendarUpdate => "/v2/destination-calendars",
            Self::SelectedCalendarAdd | Self::SelectedCalendarDelete => "/v2/selected-calendars",
            Self::ConferencingList => "/v2/conferencing",
            Self::ConferencingDefaultGet => "/v2/conferencing/default",
            Self::ConferencingDefaultSet => "/v2/conferencing/{app}/default",
            Self::ConferencingConnect => "/v2/conferencing/{app}/connect",
            Self::ConferencingDisconnect => "/v2/conferencing/{app}/disconnect",
            Self::ScheduleList | Self::ScheduleCreate => "/v2/schedules",
            Self::ScheduleDefaultGet => "/v2/schedules/default",
            Self::ScheduleGet | Self::ScheduleUpdate | Self::ScheduleDelete => {
                "/v2/schedules/{schedule_id}"
            }
            Self::WebhookList | Self::WebhookCreate => "/v2/webhooks",
            Self::WebhookGet | Self::WebhookUpdate | Self::WebhookDelete => {
                "/v2/webhooks/{webhook_id}"
            }
        }
    }

    /// Provider HTTP method.
    #[must_use]
    pub const fn method(self) -> CalDiyHttpMethod {
        match self {
            Self::ProfileGet
            | Self::EventTypeList
            | Self::EventTypeGet
            | Self::EventTypePrivateLinkList
            | Self::EventTypeWebhookList
            | Self::EventTypeWebhookGet
            | Self::SlotList
            | Self::SlotReservationGet
            | Self::BookingList
            | Self::BookingGet
            | Self::BookingGetBySeat
            | Self::BookingAttendeeList
            | Self::BookingAttendeeGet
            | Self::BookingCalendarLinksGet
            | Self::BookingReferenceList
            | Self::BookingRecordingList
            | Self::BookingTranscriptList
            | Self::BookingConferencingSessionList
            | Self::CalendarList
            | Self::CalendarProviderCheck
            | Self::CalendarIcsFeedCheck
            | Self::CalendarBusyTimeList
            | Self::CalendarConnectionList
            | Self::CalendarConnectionEventList
            | Self::CalendarConnectionEventGet
            | Self::CalendarConnectionFreeBusyGet
            | Self::CalendarEventList
            | Self::CalendarEventGet
            | Self::CalendarFreeBusyGet
            | Self::ConferencingList
            | Self::ConferencingDefaultGet
            | Self::ScheduleList
            | Self::ScheduleDefaultGet
            | Self::ScheduleGet
            | Self::WebhookList
            | Self::WebhookGet => CalDiyHttpMethod::Get,
            Self::ProfileUpdate
            | Self::EventTypeUpdate
            | Self::EventTypePrivateLinkUpdate
            | Self::EventTypeWebhookUpdate
            | Self::SlotReservationUpdate
            | Self::BookingLocationUpdate
            | Self::CalendarConnectionEventUpdate
            | Self::CalendarEventUpdate
            | Self::ScheduleUpdate
            | Self::WebhookUpdate => CalDiyHttpMethod::Patch,
            Self::DestinationCalendarUpdate => CalDiyHttpMethod::Put,
            Self::EventTypeDelete
            | Self::EventTypePrivateLinkDelete
            | Self::EventTypeWebhookDelete
            | Self::EventTypeWebhookDeleteAll
            | Self::SlotReservationDelete
            | Self::BookingAttendeeDelete
            | Self::CalendarConnectionEventDelete
            | Self::CalendarEventDelete
            | Self::SelectedCalendarDelete
            | Self::ConferencingDisconnect
            | Self::ScheduleDelete
            | Self::WebhookDelete => CalDiyHttpMethod::Delete,
            _ => CalDiyHttpMethod::Post,
        }
    }

    /// Connector-selected Cal API version header value.
    #[must_use]
    pub const fn api_version(self) -> &'static str {
        match self {
            Self::EventTypePrivateLinkList
            | Self::EventTypePrivateLinkCreate
            | Self::EventTypePrivateLinkUpdate
            | Self::EventTypePrivateLinkDelete => PRIVATE_LINKS_API_VERSION,
            Self::EventTypeList
            | Self::EventTypeGet
            | Self::EventTypeCreate
            | Self::EventTypeUpdate
            | Self::EventTypeDelete
            | Self::EventTypeWebhookList
            | Self::EventTypeWebhookGet
            | Self::EventTypeWebhookCreate
            | Self::EventTypeWebhookUpdate
            | Self::EventTypeWebhookDelete
            | Self::EventTypeWebhookDeleteAll => EVENT_TYPES_API_VERSION,
            Self::SlotList
            | Self::SlotReservationCreate
            | Self::SlotReservationGet
            | Self::SlotReservationUpdate
            | Self::SlotReservationDelete => SLOTS_API_VERSION,
            Self::ScheduleList
            | Self::ScheduleDefaultGet
            | Self::ScheduleGet
            | Self::ScheduleCreate
            | Self::ScheduleUpdate
            | Self::ScheduleDelete => SCHEDULES_API_VERSION,
            _ => GENERAL_API_VERSION,
        }
    }

    /// Whether the operation is read-only.
    #[must_use]
    pub const fn is_read(self) -> bool {
        matches!(self.method(), CalDiyHttpMethod::Get)
    }

    /// Whether request fields other than path parameters are encoded as query parameters.
    #[must_use]
    pub const fn uses_query(self) -> bool {
        !self.query_parameters().is_empty()
    }

    /// Input fields encoded as URL query parameters for this operation.
    #[must_use]
    pub const fn query_parameters(self) -> &'static [&'static str] {
        match self {
            Self::EventTypeList => &[
                "username",
                "eventSlug",
                "usernames",
                "orgSlug",
                "orgId",
                "sortCreatedAt",
            ],
            Self::SlotList => &[
                "start",
                "end",
                "eventTypeId",
                "eventTypeSlug",
                "username",
                "teamSlug",
                "organizationSlug",
                "usernames",
                "timeZone",
                "duration",
                "bookingUidToReschedule",
                "format",
            ],
            Self::BookingList => &[
                "status",
                "attendeeEmail",
                "attendeeName",
                "bookingUid",
                "eventTypeIds",
                "eventTypeId",
                "teamsIds",
                "teamId",
                "afterStart",
                "beforeEnd",
                "afterCreatedAt",
                "beforeCreatedAt",
                "afterUpdatedAt",
                "beforeUpdatedAt",
                "sortStart",
                "sortEnd",
                "sortCreated",
                "sortUpdatedAt",
                "take",
                "skip",
            ],
            Self::BookingReferenceList => &["type"],
            Self::EventTypeWebhookList | Self::WebhookList => &["skip", "take"],
            Self::CalendarBusyTimeList => &["timeZone", "dateFrom", "dateTo", "calendarsToLoad"],
            Self::CalendarConnectionEventList => &["from", "to", "timeZone", "calendarId"],
            Self::CalendarConnectionEventGet
            | Self::CalendarConnectionEventCreate
            | Self::CalendarConnectionEventUpdate
            | Self::CalendarConnectionEventDelete => &["calendarId"],
            Self::CalendarConnectionFreeBusyGet => &["from", "to", "timeZone"],
            Self::CalendarEventList => &["from", "to", "timeZone", "calendarId"],
            Self::CalendarFreeBusyGet => &["from", "to", "timeZone"],
            Self::SelectedCalendarDelete => &[
                "integration",
                "externalId",
                "credentialId",
                "delegationCredentialId",
            ],
            _ => &[],
        }
    }

    /// Whether the operation creates a new durable provider object.
    #[must_use]
    pub const fn creates_resource(self) -> bool {
        matches!(
            self,
            Self::EventTypeCreate
                | Self::EventTypePrivateLinkCreate
                | Self::EventTypeWebhookCreate
                | Self::SlotReservationCreate
                | Self::BookingCreate
                | Self::CalendarConnectionEventCreate
                | Self::CalendarEventCreate
                | Self::SelectedCalendarAdd
                | Self::ConferencingConnect
                | Self::ScheduleCreate
                | Self::WebhookCreate
        )
    }

    /// Whether the operation deletes or irreversibly transitions provider state.
    #[must_use]
    pub const fn destructive(self) -> bool {
        matches!(
            self,
            Self::EventTypeDelete
                | Self::EventTypePrivateLinkDelete
                | Self::EventTypeWebhookDelete
                | Self::EventTypeWebhookDeleteAll
                | Self::SlotReservationDelete
                | Self::BookingCancel
                | Self::BookingDecline
                | Self::BookingAttendeeDelete
                | Self::CalendarConnectionEventDelete
                | Self::CalendarEventDelete
                | Self::CalendarDisconnect
                | Self::SelectedCalendarDelete
                | Self::ConferencingDisconnect
                | Self::ScheduleDelete
                | Self::WebhookDelete
        )
    }

    /// Risk classification advertised in the AIP manifest.
    #[must_use]
    pub const fn risk(self) -> RiskLevel {
        if matches!(
            self,
            Self::BookingRecordingList | Self::BookingTranscriptList
        ) {
            RiskLevel::High
        } else if self.is_read() {
            RiskLevel::Low
        } else if self.destructive()
            || matches!(
                self,
                Self::BookingReschedule
                    | Self::BookingConfirm
                    | Self::BookingMarkAbsent
                    | Self::BookingReassign
                    | Self::BookingReassignToUser
            )
        {
            RiskLevel::High
        } else {
            RiskLevel::Medium
        }
    }

    /// Compensating capability suffix for resource creation, when Cal.diy exposes one.
    #[must_use]
    pub const fn compensation_suffix(self) -> Option<&'static str> {
        match self {
            Self::EventTypeCreate => Some("event_type.delete"),
            Self::EventTypePrivateLinkCreate => Some("event_type.private_link.delete"),
            Self::EventTypeWebhookCreate => Some("event_type.webhook.delete"),
            Self::SlotReservationCreate => Some("slot.reservation.delete"),
            Self::BookingCreate => Some("booking.cancel"),
            Self::CalendarConnectionEventCreate => Some("calendar.connection.event.delete"),
            Self::CalendarEventCreate => Some("calendar.event.delete"),
            Self::SelectedCalendarAdd => Some("calendar.selected.delete"),
            Self::ConferencingConnect => Some("conferencing.disconnect"),
            Self::ScheduleCreate => Some("schedule.delete"),
            Self::WebhookCreate => Some("webhook.delete"),
            _ => None,
        }
    }

    /// Path parameter names consumed by the route template.
    #[must_use]
    pub const fn path_parameters(self) -> &'static [&'static str] {
        match self {
            Self::EventTypeGet | Self::EventTypeUpdate | Self::EventTypeDelete => {
                &["event_type_id"]
            }
            Self::EventTypePrivateLinkList | Self::EventTypePrivateLinkCreate => &["event_type_id"],
            Self::EventTypePrivateLinkUpdate | Self::EventTypePrivateLinkDelete => {
                &["event_type_id", "link_id"]
            }
            Self::EventTypeWebhookList
            | Self::EventTypeWebhookCreate
            | Self::EventTypeWebhookDeleteAll => &["event_type_id"],
            Self::EventTypeWebhookGet
            | Self::EventTypeWebhookUpdate
            | Self::EventTypeWebhookDelete => &["event_type_id", "webhook_id"],
            Self::SlotReservationGet
            | Self::SlotReservationUpdate
            | Self::SlotReservationDelete => &["reservation_uid"],
            Self::BookingReassignToUser => &["booking_uid", "user_id"],
            Self::BookingGetBySeat => &["seat_uid"],
            Self::BookingAttendeeGet | Self::BookingAttendeeDelete => {
                &["booking_uid", "attendee_id"]
            }
            Self::BookingGet
            | Self::BookingReschedule
            | Self::BookingCancel
            | Self::BookingConfirm
            | Self::BookingDecline
            | Self::BookingMarkAbsent
            | Self::BookingReassign
            | Self::BookingLocationUpdate
            | Self::BookingAttendeeList
            | Self::BookingAttendeeAdd
            | Self::BookingGuestAdd
            | Self::BookingCalendarLinksGet
            | Self::BookingReferenceList
            | Self::BookingRecordingList
            | Self::BookingTranscriptList
            | Self::BookingConferencingSessionList => &["booking_uid"],
            Self::CalendarConnectionEventList
            | Self::CalendarConnectionEventCreate
            | Self::CalendarConnectionFreeBusyGet => &["connection_id"],
            Self::CalendarConnectionEventGet
            | Self::CalendarConnectionEventUpdate
            | Self::CalendarConnectionEventDelete => &["connection_id", "event_id"],
            Self::CalendarProviderCheck | Self::CalendarDisconnect => &["calendar"],
            Self::CalendarEventList | Self::CalendarEventCreate | Self::CalendarFreeBusyGet => {
                &["calendar"]
            }
            Self::CalendarEventGet | Self::CalendarEventUpdate | Self::CalendarEventDelete => {
                &["calendar", "event_uid"]
            }
            Self::ConferencingDefaultSet
            | Self::ConferencingConnect
            | Self::ConferencingDisconnect => &["app"],
            Self::ScheduleGet | Self::ScheduleUpdate | Self::ScheduleDelete => &["schedule_id"],
            Self::WebhookGet | Self::WebhookUpdate | Self::WebhookDelete => &["webhook_id"],
            _ => &[],
        }
    }

    /// JSON Schema for AIP action input.
    #[must_use]
    pub fn input_schema(self) -> Value {
        let identifier = |name: &str| json!({ (name): { "type": "integer" } });
        let webhook_triggers = || {
            json!({
                "type": "array",
                "minItems": 1,
                "uniqueItems": true,
                "items": { "type": "string", "enum": WEBHOOK_TRIGGERS }
            })
        };
        match self {
            Self::ProfileGet
            | Self::CalendarList
            | Self::CalendarIcsFeedCheck
            | Self::CalendarConnectionList
            | Self::ConferencingList
            | Self::ConferencingDefaultGet
            | Self::ScheduleList
            | Self::ScheduleDefaultGet => empty_schema(),
            Self::ProfileUpdate => profile_update_schema(),
            Self::EventTypeList => event_type_list_schema(),
            Self::BookingList => booking_list_schema(),
            Self::WebhookList => pagination_schema(),
            Self::EventTypeGet | Self::EventTypeDelete => {
                object_schema(&["event_type_id"], identifier("event_type_id"), false)
            }
            Self::EventTypeCreate => event_type_create_schema(),
            Self::EventTypeUpdate => event_type_update_schema(),
            Self::EventTypePrivateLinkList => {
                object_schema(&["event_type_id"], identifier("event_type_id"), false)
            }
            Self::EventTypePrivateLinkCreate => object_schema(
                &["event_type_id"],
                json!({
                    "event_type_id": { "type": "integer" },
                    "expiresAt": { "type": "string", "format": "date-time" },
                    "maxUsageCount": { "type": "integer", "minimum": 1 }
                }),
                false,
            ),
            Self::EventTypePrivateLinkUpdate => object_schema(
                &["event_type_id", "link_id"],
                json!({
                    "event_type_id": { "type": "integer" },
                    "link_id": { "type": "string", "minLength": 1 },
                    "expiresAt": { "type": "string", "format": "date-time" },
                    "maxUsageCount": { "type": "integer", "minimum": 1 }
                }),
                false,
            ),
            Self::EventTypePrivateLinkDelete => object_schema(
                &["event_type_id", "link_id"],
                json!({
                    "event_type_id": { "type": "integer" },
                    "link_id": { "type": "string", "minLength": 1 }
                }),
                false,
            ),
            Self::EventTypeWebhookList => object_schema(
                &["event_type_id"],
                json!({
                    "event_type_id": { "type": "integer" },
                    "skip": { "type": "integer", "minimum": 0 },
                    "take": { "type": "integer", "minimum": 1, "maximum": 250 }
                }),
                false,
            ),
            Self::EventTypeWebhookGet | Self::EventTypeWebhookDelete => object_schema(
                &["event_type_id", "webhook_id"],
                json!({
                    "event_type_id": { "type": "integer" },
                    "webhook_id": { "type": "string", "minLength": 1 }
                }),
                false,
            ),
            Self::EventTypeWebhookCreate => object_schema(
                &[
                    "event_type_id",
                    "active",
                    "subscriberUrl",
                    "triggers",
                    "webhook_secret_ref",
                ],
                json!({
                    "event_type_id": { "type": "integer" },
                    "active": { "type": "boolean" },
                    "subscriberUrl": { "type": "string", "format": "uri" },
                    "triggers": webhook_triggers(),
                    "webhook_secret_ref": {
                        "type": "string",
                        "pattern": "^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$"
                    },
                    "version": { "const": "2021-10-20" }
                }),
                false,
            ),
            Self::EventTypeWebhookUpdate => object_schema(
                &["event_type_id", "webhook_id"],
                json!({
                    "event_type_id": { "type": "integer" },
                    "webhook_id": { "type": "string", "minLength": 1 },
                    "active": { "type": "boolean" },
                    "subscriberUrl": { "type": "string", "format": "uri" },
                    "triggers": webhook_triggers(),
                    "webhook_secret_ref": {
                        "type": "string",
                        "pattern": "^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$"
                    },
                    "version": { "const": "2021-10-20" }
                }),
                false,
            ),
            Self::EventTypeWebhookDeleteAll => {
                object_schema(&["event_type_id"], identifier("event_type_id"), false)
            }
            Self::SlotList => slot_list_schema(),
            Self::SlotReservationCreate => object_schema(
                &["eventTypeId", "slotStart"],
                json!({
                    "eventTypeId": { "type": "integer" },
                    "slotStart": { "type": "string", "format": "date-time" },
                    "slotDuration": { "type": "integer", "minimum": 1 },
                    "reservationDuration": { "type": "integer", "minimum": 1 }
                }),
                false,
            ),
            Self::SlotReservationGet | Self::SlotReservationDelete => object_schema(
                &["reservation_uid"],
                json!({ "reservation_uid": { "type": "string", "minLength": 1 } }),
                false,
            ),
            Self::SlotReservationUpdate => object_schema(
                &["reservation_uid", "eventTypeId", "slotStart"],
                json!({
                    "reservation_uid": { "type": "string", "minLength": 1 },
                    "eventTypeId": { "type": "integer" },
                    "slotStart": { "type": "string", "format": "date-time" },
                    "slotDuration": { "type": "integer", "minimum": 1 },
                    "reservationDuration": { "type": "integer", "minimum": 1 }
                }),
                false,
            ),
            Self::BookingGetBySeat => object_schema(
                &["seat_uid"],
                json!({ "seat_uid": { "type": "string", "minLength": 1 } }),
                false,
            ),
            Self::BookingGet
            | Self::BookingConfirm
            | Self::BookingReassign
            | Self::BookingAttendeeList
            | Self::BookingCalendarLinksGet
            | Self::BookingRecordingList
            | Self::BookingTranscriptList
            | Self::BookingConferencingSessionList => object_schema(
                &["booking_uid"],
                json!({ "booking_uid": { "type": "string", "minLength": 1 } }),
                false,
            ),
            Self::BookingCreate => booking_create_schema(),
            Self::BookingReschedule => booking_reschedule_schema(),
            Self::BookingCancel => booking_cancel_schema(),
            Self::BookingDecline => booking_decline_schema(),
            Self::BookingMarkAbsent => booking_mark_absent_schema(),
            Self::BookingLocationUpdate => booking_location_update_schema(),
            Self::BookingAttendeeAdd => booking_attendee_add_schema(),
            Self::BookingGuestAdd => booking_guest_add_schema(),
            Self::BookingReferenceList => booking_reference_list_schema(),
            Self::BookingReassignToUser => object_schema(
                &["booking_uid", "user_id"],
                json!({
                    "booking_uid": { "type": "string", "minLength": 1 },
                    "user_id": { "type": "integer" },
                    "reason": { "type": "string" }
                }),
                false,
            ),
            Self::BookingAttendeeGet | Self::BookingAttendeeDelete => object_schema(
                &["booking_uid", "attendee_id"],
                json!({
                    "booking_uid": { "type": "string", "minLength": 1 },
                    "attendee_id": { "type": "integer" }
                }),
                false,
            ),
            Self::CalendarBusyTimeList => object_schema(
                &["timeZone", "dateFrom", "dateTo", "calendarsToLoad"],
                json!({
                    "timeZone": { "type": "string", "minLength": 1 },
                    "dateFrom": iso_date_or_datetime_schema(),
                    "dateTo": iso_date_or_datetime_schema(),
                    "calendarsToLoad": {
                        "type": "array",
                        "minItems": 1,
                        "items": {
                            "type": "object",
                            "required": ["credentialId", "externalId"],
                            "properties": {
                                "credentialId": { "type": "integer" },
                                "externalId": { "type": "string", "minLength": 1 }
                            },
                            "additionalProperties": false
                        }
                    }
                }),
                false,
            ),
            Self::CalendarProviderCheck => object_schema(
                &["calendar"],
                json!({
                    "calendar": { "type": "string", "enum": ["google", "office365", "apple"] }
                }),
                false,
            ),
            Self::CalendarDisconnect => object_schema(
                &["calendar", "id"],
                json!({
                    "calendar": { "type": "string", "enum": ["google", "office365", "apple"] },
                    "id": { "type": "integer" }
                }),
                false,
            ),
            Self::CalendarConnectionEventList => object_schema(
                &["connection_id", "from", "to"],
                json!({
                    "connection_id": { "type": "integer" },
                    "from": iso_date_or_datetime_schema(),
                    "to": iso_date_or_datetime_schema(),
                    "timeZone": { "type": "string", "minLength": 1 },
                    "calendarId": { "type": "string", "minLength": 1 }
                }),
                false,
            ),
            Self::CalendarConnectionEventGet | Self::CalendarConnectionEventDelete => {
                object_schema(
                    &["connection_id", "event_id"],
                    json!({
                        "connection_id": { "type": "integer" },
                        "event_id": { "type": "string", "minLength": 1 },
                        "calendarId": { "type": "string", "minLength": 1 }
                    }),
                    false,
                )
            }
            Self::CalendarConnectionEventCreate => object_schema(
                &["connection_id", "title", "start", "end"],
                calendar_event_create_properties(
                    json!({ "connection_id": { "type": "integer" } }),
                    true,
                ),
                false,
            ),
            Self::CalendarConnectionEventUpdate => object_schema(
                &["connection_id", "event_id"],
                calendar_event_update_properties(json!({
                    "connection_id": { "type": "integer" },
                    "event_id": { "type": "string", "minLength": 1 },
                    "calendarId": { "type": "string", "minLength": 1 }
                })),
                false,
            ),
            Self::CalendarConnectionFreeBusyGet => object_schema(
                &["connection_id", "from", "to"],
                json!({
                    "connection_id": { "type": "integer" },
                    "from": iso_date_or_datetime_schema(),
                    "to": iso_date_or_datetime_schema(),
                    "timeZone": { "type": "string", "minLength": 1 }
                }),
                false,
            ),
            Self::CalendarEventList => object_schema(
                &["calendar", "from", "to"],
                json!({
                    "calendar": { "const": "google" },
                    "from": iso_date_or_datetime_schema(),
                    "to": iso_date_or_datetime_schema(),
                    "timeZone": { "type": "string", "minLength": 1 },
                    "calendarId": { "type": "string", "minLength": 1 }
                }),
                false,
            ),
            Self::CalendarEventGet | Self::CalendarEventDelete => object_schema(
                &["calendar", "event_uid"],
                json!({
                    "calendar": { "const": "google" },
                    "event_uid": { "type": "string", "minLength": 1 }
                }),
                false,
            ),
            Self::CalendarEventCreate => object_schema(
                &["calendar", "title", "start", "end"],
                calendar_event_create_properties(
                    json!({ "calendar": { "const": "google" } }),
                    false,
                ),
                false,
            ),
            Self::CalendarEventUpdate => object_schema(
                &["calendar", "event_uid"],
                calendar_event_update_properties(json!({
                    "calendar": { "const": "google" },
                    "event_uid": { "type": "string", "minLength": 1 }
                })),
                false,
            ),
            Self::CalendarFreeBusyGet => object_schema(
                &["calendar", "from", "to"],
                json!({
                    "calendar": { "const": "google" },
                    "from": iso_date_or_datetime_schema(),
                    "to": iso_date_or_datetime_schema(),
                    "timeZone": { "type": "string", "minLength": 1 }
                }),
                false,
            ),
            Self::DestinationCalendarUpdate => object_schema(
                &["integration", "externalId"],
                json!({
                    "integration": {
                        "type": "string",
                        "enum": ["apple_calendar", "google_calendar", "office365_calendar"]
                    },
                    "externalId": { "type": "string", "minLength": 1 },
                    "delegationCredentialId": { "type": "string", "minLength": 1 }
                }),
                false,
            ),
            Self::SelectedCalendarAdd => object_schema(
                &["integration", "externalId", "credentialId"],
                json!({
                    "integration": { "type": "string", "minLength": 1 },
                    "externalId": { "type": "string", "minLength": 1 },
                    "credentialId": { "type": "integer" },
                    "delegationCredentialId": { "type": "string", "minLength": 1 }
                }),
                false,
            ),
            Self::SelectedCalendarDelete => object_schema(
                &["integration", "externalId", "credentialId"],
                json!({
                    "integration": { "type": "string", "minLength": 1 },
                    "externalId": { "type": "string", "minLength": 1 },
                    "credentialId": { "type": "string", "minLength": 1 },
                    "delegationCredentialId": { "type": "string", "minLength": 1 }
                }),
                false,
            ),
            Self::ConferencingDefaultSet => object_schema(
                &["app"],
                json!({
                    "app": { "type": "string", "enum": ["google-meet", "zoom", "msteams", "daily-video"] }
                }),
                false,
            ),
            Self::ConferencingDisconnect => object_schema(
                &["app"],
                json!({
                    "app": { "type": "string", "enum": ["google-meet", "zoom", "msteams"] }
                }),
                false,
            ),
            Self::ConferencingConnect => object_schema(
                &["app"],
                json!({ "app": { "const": "google-meet" } }),
                false,
            ),
            Self::ScheduleGet | Self::ScheduleDelete => object_schema(
                &["schedule_id"],
                json!({ "schedule_id": { "type": "integer" } }),
                false,
            ),
            Self::ScheduleCreate => schedule_create_schema(),
            Self::ScheduleUpdate => schedule_update_schema(),
            Self::WebhookGet | Self::WebhookDelete => object_schema(
                &["webhook_id"],
                json!({ "webhook_id": { "type": "string", "minLength": 1 } }),
                false,
            ),
            Self::WebhookCreate => object_schema(
                &["active", "subscriberUrl", "triggers", "webhook_secret_ref"],
                json!({
                    "active": { "type": "boolean" },
                    "subscriberUrl": { "type": "string", "format": "uri" },
                    "triggers": webhook_triggers(),
                    "webhook_secret_ref": {
                        "type": "string",
                        "pattern": "^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$"
                    },
                    "version": { "const": "2021-10-20" }
                }),
                false,
            ),
            Self::WebhookUpdate => object_schema(
                &["webhook_id"],
                json!({
                    "webhook_id": { "type": "string", "minLength": 1 },
                    "active": { "type": "boolean" },
                    "subscriberUrl": { "type": "string", "format": "uri" },
                    "triggers": webhook_triggers(),
                    "webhook_secret_ref": {
                        "type": "string",
                        "pattern": "^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$"
                    },
                    "version": { "const": "2021-10-20" }
                }),
                false,
            ),
        }
    }
}

fn profile_update_schema() -> Value {
    object_schema(
        &[],
        json!({
            "email": { "type": "string", "format": "email" },
            "name": { "type": "string" },
            "timeFormat": { "type": "integer", "enum": [12, 24] },
            "defaultScheduleId": { "type": "integer" },
            "weekStart": { "type": "string", "enum": WEEK_DAYS },
            "timeZone": { "type": "string", "minLength": 1 },
            "locale": { "type": "string", "enum": CAL_DIY_LOCALES },
            "avatarUrl": { "type": "string", "format": "uri" },
            "bio": { "type": "string" },
            "metadata": {
                "type": "object",
                "maxProperties": 50,
                "propertyNames": { "maxLength": 40 },
                "additionalProperties": {
                    "type": ["string", "boolean", "number"],
                    "maxLength": 500
                }
            }
        }),
        false,
    )
}

fn event_type_list_schema() -> Value {
    object_schema(
        &[],
        json!({
            "username": { "type": "string", "minLength": 1 },
            "eventSlug": { "type": "string", "minLength": 1 },
            "usernames": { "type": "array", "minItems": 1, "items": { "type": "string" } },
            "orgSlug": { "type": "string", "minLength": 1 },
            "orgId": { "type": "integer" },
            "sortCreatedAt": { "type": "string", "enum": ["asc", "desc"] }
        }),
        false,
    )
}

fn event_type_create_schema() -> Value {
    let schema = object_schema(
        &["title", "slug", "lengthInMinutes"],
        event_type_properties(),
        false,
    );
    forbid_active_recurrence_with_booker_limit(schema)
}

fn event_type_update_schema() -> Value {
    let mut properties = object_properties(event_type_properties());
    properties.insert("event_type_id".to_owned(), json!({ "type": "integer" }));
    let schema = object_schema(&["event_type_id"], Value::Object(properties), false);
    forbid_active_recurrence_with_booker_limit(schema)
}

fn event_type_properties() -> Value {
    let mut properties = object_properties(json!({
        "lengthInMinutesOptions": {
            "type": "array",
            "minItems": 1,
            "uniqueItems": true,
            "items": { "type": "integer", "minimum": 1 }
        },
        "title": { "type": "string", "minLength": 1 },
        "slug": { "type": "string", "minLength": 1 },
        "description": { "type": "string" },
        "bookingFields": {
            "type": "array",
            "minItems": 1,
            "items": event_type_booking_field_schema()
        },
        "disableGuests": { "type": "boolean" },
        "slotInterval": { "type": "integer" },
        "minimumBookingNotice": { "type": "integer", "minimum": 0 },
        "beforeEventBuffer": { "type": "integer" },
        "afterEventBuffer": { "type": "integer" },
        "scheduleId": { "type": "integer" },
        "bookingLimitsCount": event_type_period_limits_schema(1),
        "bookerActiveBookingsLimit": event_type_booker_limit_schema(),
        "onlyShowFirstAvailableSlot": { "type": "boolean" },
        "bookingLimitsDuration": event_type_period_limits_schema(15),
        "bookingWindow": event_type_booking_window_schema(),
        "offsetStart": { "type": "integer", "minimum": 0 },
        "bookerLayouts": {
            "type": "object",
            "required": ["defaultLayout", "enabledLayouts"],
            "properties": {
                "defaultLayout": { "type": "string", "enum": ["month", "week", "column"] },
                "enabledLayouts": {
                    "type": "array",
                    "minItems": 1,
                    "uniqueItems": true,
                    "items": { "type": "string", "enum": ["month", "week", "column"] }
                }
            },
            "additionalProperties": false
        },
        "confirmationPolicy": event_type_confirmation_policy_schema(),
        "recurrence": {
            "oneOf": [
                disabled_schema(),
                {
                    "type": "object",
                    "required": ["interval", "occurrences", "frequency"],
                    "properties": {
                        "interval": { "type": "integer", "minimum": 1 },
                        "occurrences": { "type": "integer", "minimum": 1 },
                        "frequency": { "type": "string", "enum": ["yearly", "monthly", "weekly"] },
                        "disabled": { "const": false }
                    },
                    "additionalProperties": false
                }
            ]
        },
        "requiresBookerEmailVerification": { "type": "boolean" },
        "hideCalendarNotes": { "type": "boolean" },
        "lockTimeZoneToggleOnBookingPage": { "type": "boolean" },
        "color": {
            "type": "object",
            "required": ["lightThemeHex", "darkThemeHex"],
            "properties": {
                "lightThemeHex": { "type": "string", "pattern": "^#[0-9A-Fa-f]{6}$" },
                "darkThemeHex": { "type": "string", "pattern": "^#[0-9A-Fa-f]{6}$" }
            },
            "additionalProperties": false
        },
        "seats": {
            "oneOf": [
                disabled_schema(),
                {
                    "type": "object",
                    "required": ["seatsPerTimeSlot", "showAttendeeInfo", "showAvailabilityCount"],
                    "properties": {
                        "seatsPerTimeSlot": { "type": "integer", "minimum": 1, "maximum": 1000 },
                        "showAttendeeInfo": { "type": "boolean" },
                        "showAvailabilityCount": { "type": "boolean" },
                        "disabled": { "const": false }
                    },
                    "additionalProperties": false
                }
            ]
        },
        "customName": { "type": "string" },
        "destinationCalendar": {
            "type": "object",
            "required": ["integration", "externalId"],
            "properties": {
                "integration": { "type": "string", "minLength": 1 },
                "externalId": { "type": "string", "minLength": 1 }
            },
            "additionalProperties": false
        },
        "useDestinationCalendarEmail": { "type": "boolean" },
        "hideCalendarEventDetails": { "type": "boolean" },
        "successRedirectUrl": { "type": "string", "format": "uri" },
        "hideOrganizerEmail": { "type": "boolean" },
        "calVideoSettings": {
            "type": "object",
            "properties": {
                "disableRecordingForOrganizer": { "type": "boolean" },
                "disableRecordingForGuests": { "type": "boolean" },
                "redirectUrlOnExit": { "type": ["string", "null"], "format": "uri" },
                "enableAutomaticRecordingForOrganizer": { "type": "boolean" },
                "enableAutomaticTranscription": { "type": "boolean" },
                "disableTranscriptionForGuests": { "type": "boolean" },
                "disableTranscriptionForOrganizer": { "type": "boolean" },
                "sendTranscriptionEmails": { "type": "boolean" }
            },
            "additionalProperties": false
        },
        "hidden": { "type": "boolean" },
        "bookingRequiresAuthentication": { "type": "boolean" },
        "disableCancelling": {
            "type": "object",
            "properties": { "disabled": { "type": "boolean" } },
            "additionalProperties": false
        },
        "disableRescheduling": {
            "type": "object",
            "properties": {
                "disabled": { "type": "boolean" },
                "minutesBefore": { "type": "integer", "minimum": 1 }
            },
            "additionalProperties": false
        },
        "interfaceLanguage": { "type": "string", "enum": EVENT_TYPE_INTERFACE_LANGUAGES },
        "allowReschedulingPastBookings": { "type": "boolean" },
        "allowReschedulingCancelledBookings": { "type": "boolean" },
        "showOptimizedSlots": { "type": "boolean" },
        "locations": {
            "type": "array",
            "minItems": 1,
            "items": event_type_location_schema()
        }
    }));
    properties.insert(
        "lengthInMinutes".to_owned(),
        json!({ "type": "integer", "minimum": 1 }),
    );
    Value::Object(properties)
}

fn disabled_schema() -> Value {
    json!({
        "type": "object",
        "required": ["disabled"],
        "properties": { "disabled": { "const": true } },
        "additionalProperties": false
    })
}

fn event_type_period_limits_schema(minimum: u64) -> Value {
    let active = json!({
        "type": "object",
        "minProperties": 1,
        "properties": {
            "day": { "type": "integer", "minimum": minimum },
            "week": { "type": "integer", "minimum": minimum },
            "month": { "type": "integer", "minimum": minimum },
            "year": { "type": "integer", "minimum": minimum },
            "disabled": { "const": false }
        },
        "additionalProperties": false,
        "anyOf": [
            { "required": ["day"] },
            { "required": ["week"] },
            { "required": ["month"] },
            { "required": ["year"] }
        ]
    });
    json!({ "oneOf": [disabled_schema(), active] })
}

fn event_type_booker_limit_schema() -> Value {
    json!({
        "oneOf": [
            disabled_schema(),
            {
                "type": "object",
                "properties": {
                    "maximumActiveBookings": { "type": "integer", "minimum": 1 },
                    "offerReschedule": { "type": "boolean" },
                    "disabled": { "const": false }
                },
                "additionalProperties": false,
                "anyOf": [
                    { "required": ["maximumActiveBookings"] },
                    { "required": ["offerReschedule"] }
                ]
            }
        ]
    })
}

fn event_type_booking_window_schema() -> Value {
    let rolling = |kind: &str| {
        json!({
            "type": "object",
            "required": ["type", "value"],
            "properties": {
                "type": { "const": kind },
                "value": { "type": "number", "minimum": 0 },
                "rolling": { "type": "boolean" },
                "disabled": { "const": false }
            },
            "additionalProperties": false
        })
    };
    json!({
        "oneOf": [
            disabled_schema(),
            rolling("businessDays"),
            rolling("calendarDays"),
            {
                "type": "object",
                "required": ["type", "value"],
                "properties": {
                    "type": { "const": "range" },
                    "value": {
                        "type": "array",
                        "minItems": 1,
                        "items": iso_date_or_datetime_schema()
                    },
                    "disabled": { "const": false }
                },
                "additionalProperties": false
            }
        ]
    })
}

fn event_type_confirmation_policy_schema() -> Value {
    let base = |kind: &str, notice_threshold: Value, require_notice_threshold: bool| {
        let required = if require_notice_threshold {
            json!([
                "type",
                "blockUnconfirmedBookingsInBooker",
                "noticeThreshold"
            ])
        } else {
            json!(["type", "blockUnconfirmedBookingsInBooker"])
        };
        json!({
            "type": "object",
            "required": required,
            "properties": {
                "type": { "const": kind },
                "noticeThreshold": notice_threshold,
                "blockUnconfirmedBookingsInBooker": { "type": "boolean" },
                "disabled": { "const": false }
            },
            "additionalProperties": false
        })
    };
    let threshold = json!({
        "type": "object",
        "required": ["unit", "count"],
        "properties": {
            "unit": { "type": "string", "enum": ["minutes", "hours"] },
            "count": { "type": "integer", "minimum": 1 }
        },
        "additionalProperties": false
    });
    json!({
        "oneOf": [
            disabled_schema(),
            base("always", threshold.clone(), false),
            base("time", threshold, true)
        ]
    })
}

fn event_type_location_schema() -> Value {
    let marker = |kind: &str| {
        json!({
            "type": "object",
            "required": ["type"],
            "properties": { "type": { "const": kind } },
            "additionalProperties": false
        })
    };
    let value = |kind: &str, field: &str, field_schema: Value, public: bool| {
        let mut required = vec![
            Value::String("type".to_owned()),
            Value::String(field.to_owned()),
        ];
        let mut properties = serde_json::Map::from_iter([
            ("type".to_owned(), json!({ "const": kind })),
            (field.to_owned(), field_schema),
        ]);
        if public {
            required.push(Value::String("public".to_owned()));
            properties.insert("public".to_owned(), json!({ "type": "boolean" }));
        }
        json!({
            "type": "object",
            "required": required,
            "properties": properties,
            "additionalProperties": false
        })
    };
    json!({
        "oneOf": [
            value("address", "address", json!({ "type": "string", "minLength": 1 }), true),
            value("link", "link", json!({ "type": "string", "format": "uri" }), true),
            value(
                "integration",
                "integration",
                json!({
                    "type": "string",
                    "enum": [
                        "cal-video", "google-meet", "zoom", "whereby-video", "whatsapp-video",
                        "webex-video", "telegram-video", "tandem", "sylaps-video", "skype-video",
                        "sirius-video", "signal-video", "shimmer-video", "salesroom-video",
                        "roam-video", "riverside-video", "ping-video", "office365-video",
                        "mirotalk-video", "jitsi", "jelly-video", "jelly-conferencing", "huddle",
                        "facetime-video", "element-call-video", "eightxeight-video", "discord-video",
                        "demodesk-video", "campfire-video"
                    ]
                }),
                false,
            ),
            value(
                "phone",
                "phone",
                json!({ "type": "string", "pattern": "^\\+[1-9][0-9]{6,14}$" }),
                true,
            ),
            marker("attendeeAddress"),
            marker("attendeePhone"),
            marker("attendeeDefined")
        ]
    })
}

fn event_type_booking_field_schema() -> Value {
    let custom = |kind: &str, placeholder: bool, options: bool| {
        let mut properties = serde_json::Map::from_iter([
            ("type".to_owned(), json!({ "const": kind })),
            (
                "slug".to_owned(),
                json!({ "type": "string", "minLength": 1 }),
            ),
            ("label".to_owned(), json!({ "type": "string" })),
            ("required".to_owned(), json!({ "type": "boolean" })),
            ("disableOnPrefill".to_owned(), json!({ "type": "boolean" })),
            ("hidden".to_owned(), json!({ "type": "boolean" })),
        ]);
        if placeholder {
            properties.insert("placeholder".to_owned(), json!({ "type": "string" }));
        }
        if options {
            properties.insert(
                "options".to_owned(),
                json!({
                    "type": "array",
                    "minItems": 1,
                    "items": { "type": "string" }
                }),
            );
        }
        let mut required = vec!["type", "slug", "label", "required"];
        if options {
            required.push("options");
        }
        object_schema(&required, Value::Object(properties), false)
    };
    let default_type = |kind: &str, properties: Value| {
        let mut fields = object_properties(properties);
        fields.insert("type".to_owned(), json!({ "const": kind }));
        object_schema(&["type"], Value::Object(fields), false)
    };
    let default_slug = |slug: &str, properties: Value| {
        let mut fields = object_properties(properties);
        fields.insert("slug".to_owned(), json!({ "const": slug }));
        object_schema(&["slug"], Value::Object(fields), false)
    };
    let common_default = json!({
        "label": { "type": "string" },
        "placeholder": { "type": "string" },
        "required": { "type": "boolean" },
        "hidden": { "type": "boolean" },
        "disableOnPrefill": { "type": "boolean" }
    });
    json!({
        "oneOf": [
            default_type("name", json!({
                "label": { "type": "string" },
                "placeholder": { "type": "string" },
                "disableOnPrefill": { "type": "boolean" }
            })),
            default_type("splitName", json!({
                "firstNameLabel": { "type": "string" },
                "firstNamePlaceholder": { "type": "string" },
                "lastNameLabel": { "type": "string" },
                "lastNamePlaceholder": { "type": "string" },
                "lastNameRequired": { "type": "boolean" },
                "disableOnPrefill": { "type": "boolean" }
            })),
            default_type("email", common_default.clone()),
            default_slug("title", common_default.clone()),
            default_slug("location", json!({ "label": { "type": "string" } })),
            default_slug("notes", common_default.clone()),
            default_slug("guests", common_default.clone()),
            default_slug("rescheduleReason", common_default),
            custom("phone", true, false),
            custom("address", true, false),
            custom("text", true, false),
            custom("url", true, false),
            custom("number", true, false),
            custom("textarea", true, false),
            custom("select", true, true),
            custom("multiselect", false, true),
            custom("multiemail", true, false),
            custom("checkbox", false, true),
            custom("radio", false, true),
            custom("boolean", false, false)
        ]
    })
}

fn forbid_active_recurrence_with_booker_limit(mut schema: Value) -> Value {
    if let Some(object) = schema.as_object_mut() {
        object.insert(
            "not".to_owned(),
            json!({
                "allOf": [
                    {
                        "required": ["recurrence"],
                        "properties": { "recurrence": { "required": ["interval"] } }
                    },
                    {
                        "required": ["bookerActiveBookingsLimit"],
                        "properties": {
                            "bookerActiveBookingsLimit": {
                                "anyOf": [
                                    { "required": ["maximumActiveBookings"] },
                                    { "required": ["offerReschedule"] }
                                ]
                            }
                        }
                    }
                ]
            }),
        );
    }
    schema
}

fn pagination_schema() -> Value {
    object_schema(
        &[],
        json!({
            "skip": { "type": "integer", "minimum": 0 },
            "take": { "type": "integer", "minimum": 1, "maximum": 250 }
        }),
        false,
    )
}

fn iso_date_or_datetime_schema() -> Value {
    json!({
        "anyOf": [
            { "type": "string", "format": "date" },
            { "type": "string", "format": "date-time" }
        ]
    })
}

fn slot_list_schema() -> Value {
    let shared = json!({
        "start": iso_date_or_datetime_schema(),
        "end": iso_date_or_datetime_schema(),
        "timeZone": { "type": "string", "minLength": 1 },
        "duration": { "type": "integer", "minimum": 1 },
        "bookingUidToReschedule": { "type": "string", "minLength": 1 },
        "format": { "type": "string", "enum": ["time", "range"] }
    });
    let branch = |required: &[&str], selector: Value| {
        let mut properties = object_properties(shared.clone());
        properties.extend(object_properties(selector));
        object_schema(required, Value::Object(properties), false)
    };
    json!({
        "oneOf": [
            branch(
                &["start", "end", "eventTypeId"],
                json!({ "eventTypeId": { "type": "integer" } }),
            ),
            branch(
                &["start", "end", "eventTypeSlug", "username"],
                json!({
                    "eventTypeSlug": { "type": "string", "minLength": 1 },
                    "username": { "type": "string", "minLength": 1 },
                    "organizationSlug": { "type": "string", "minLength": 1 }
                }),
            ),
            branch(
                &["start", "end", "eventTypeSlug", "teamSlug"],
                json!({
                    "eventTypeSlug": { "type": "string", "minLength": 1 },
                    "teamSlug": { "type": "string", "minLength": 1 },
                    "organizationSlug": { "type": "string", "minLength": 1 }
                }),
            ),
            branch(
                &["start", "end", "usernames", "organizationSlug"],
                json!({
                    "usernames": {
                        "type": "array",
                        "minItems": 2,
                        "uniqueItems": true,
                        "items": { "type": "string", "minLength": 1 }
                    },
                    "organizationSlug": { "type": "string", "minLength": 1 }
                }),
            )
        ]
    })
}

fn booking_list_schema() -> Value {
    let iso = || json!({ "type": "string", "format": "date-time" });
    object_schema(
        &[],
        json!({
            "status": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": true,
                "items": {
                    "type": "string",
                    "enum": ["upcoming", "recurring", "past", "cancelled", "unconfirmed"]
                }
            },
            "attendeeEmail": { "type": "string", "format": "email" },
            "attendeeName": { "type": "string" },
            "bookingUid": { "type": "string", "minLength": 1 },
            "eventTypeIds": {
                "type": "array",
                "minItems": 1,
                "items": { "type": "integer" }
            },
            "eventTypeId": { "type": "integer" },
            "teamsIds": {
                "type": "array",
                "minItems": 1,
                "items": { "type": "integer" }
            },
            "teamId": { "type": "integer" },
            "afterStart": iso(),
            "beforeEnd": iso(),
            "afterCreatedAt": iso(),
            "beforeCreatedAt": iso(),
            "afterUpdatedAt": iso(),
            "beforeUpdatedAt": iso(),
            "sortStart": { "type": "string", "enum": ["asc", "desc"] },
            "sortEnd": { "type": "string", "enum": ["asc", "desc"] },
            "sortCreated": { "type": "string", "enum": ["asc", "desc"] },
            "sortUpdatedAt": { "type": "string", "enum": ["asc", "desc"] },
            "take": { "type": "integer", "minimum": 1, "maximum": 250 },
            "skip": { "type": "integer", "minimum": 0 }
        }),
        false,
    )
}

fn booking_create_schema() -> Value {
    let attendee = booking_attendee_schema(false);
    let schema = object_schema(
        &["start", "attendee"],
        json!({
            "start": { "type": "string", "format": "date-time" },
            "attendee": attendee,
            "bookingFieldsResponses": { "type": "object", "additionalProperties": true },
            "eventTypeId": { "type": "integer" },
            "eventTypeSlug": { "type": "string", "minLength": 1 },
            "username": { "type": "string", "minLength": 1 },
            "teamSlug": { "type": "string", "minLength": 1 },
            "organizationSlug": { "type": "string", "minLength": 1 },
            "guests": {
                "type": "array",
                "uniqueItems": true,
                "items": { "type": "string", "format": "email" }
            },
            "meetingUrl": { "type": "string", "format": "uri", "deprecated": true },
            "location": booking_location_schema(false),
            "metadata": {
                "type": "object",
                "maxProperties": 46,
                "propertyNames": { "maxLength": 40 },
                "additionalProperties": { "type": "string", "maxLength": 500 }
            },
            "lengthInMinutes": { "type": "integer", "minimum": 1 },
            "routing": {
                "type": "object",
                "required": ["responseId", "teamMemberIds"],
                "properties": {
                    "responseId": { "type": "integer" },
                    "teamMemberIds": {
                        "type": "array",
                        "items": { "type": "integer" }
                    },
                    "teamMemberEmail": { "type": "string", "format": "email" },
                    "skipContactOwner": { "type": "boolean" },
                    "crmAppSlug": { "type": "string" },
                    "crmOwnerRecordType": { "type": "string" }
                },
                "additionalProperties": false
            },
            "emailVerificationCode": { "type": "string" },
            "recurrenceCount": { "type": "integer", "minimum": 1 }
        }),
        false,
    );
    with_one_of(
        schema,
        json!([
            { "required": ["eventTypeId"] },
            { "required": ["eventTypeSlug", "username"] },
            { "required": ["eventTypeSlug", "teamSlug"] }
        ]),
    )
}

fn booking_attendee_schema(email_required: bool) -> Value {
    let required = if email_required {
        json!(["name", "timeZone", "email"])
    } else {
        json!(["name", "timeZone"])
    };
    let mut schema = json!({
        "type": "object",
        "required": required,
        "properties": {
            "name": { "type": "string", "minLength": 1 },
            "timeZone": { "type": "string", "minLength": 1 },
            "email": { "type": "string", "format": "email" },
            "phoneNumber": { "type": "string", "pattern": "^\\+[1-9][0-9]{6,14}$" },
            "language": { "type": "string", "enum": CAL_DIY_LOCALES }
        },
        "additionalProperties": false
    });
    if !email_required && let Some(object) = schema.as_object_mut() {
        object.insert(
            "anyOf".to_owned(),
            json!([{ "required": ["email"] }, { "required": ["phoneNumber"] }]),
        );
    }
    schema
}

fn booking_location_schema(update: bool) -> Value {
    let discriminator_only = |kind: &str| {
        json!({
            "type": "object",
            "required": ["type"],
            "properties": { "type": { "const": kind } },
            "additionalProperties": false
        })
    };
    let with_value = |kind: &str, field: &str, schema: Value| {
        json!({
            "type": "object",
            "required": ["type", field],
            "properties": { "type": { "const": kind }, (field): schema },
            "additionalProperties": false
        })
    };
    let integration = json!({
        "type": "object",
        "required": ["type", "integration"],
        "properties": {
            "type": { "const": "integration" },
            "integration": {
                "type": "string",
                "enum": [
                    "cal-video", "google-meet", "zoom", "whereby-video", "whatsapp-video",
                    "webex-video", "telegram-video", "tandem", "sylaps-video", "skype-video",
                    "sirius-video", "signal-video", "shimmer-video", "salesroom-video",
                    "roam-video", "riverside-video", "ping-video", "office365-video",
                    "mirotalk-video", "jitsi", "jelly-video", "jelly-conferencing", "huddle",
                    "facetime-video", "element-call-video", "eightxeight-video", "discord-video",
                    "demodesk-video", "campfire-video"
                ]
            }
        },
        "additionalProperties": false
    });
    let mut alternatives = vec![
        integration,
        with_value(
            "attendeeAddress",
            "address",
            json!({ "type": "string", "minLength": 1 }),
        ),
        with_value(
            "attendeePhone",
            "phone",
            json!({ "type": "string", "pattern": "^\\+[1-9][0-9]{6,14}$" }),
        ),
        with_value(
            "attendeeDefined",
            "location",
            json!({ "type": "string", "minLength": 1 }),
        ),
    ];
    if update {
        alternatives.extend([
            with_value(
                "address",
                "address",
                json!({ "type": "string", "minLength": 1 }),
            ),
            with_value("link", "link", json!({ "type": "string", "format": "uri" })),
            with_value(
                "phone",
                "phone",
                json!({ "type": "string", "pattern": "^\\+[1-9][0-9]{6,14}$" }),
            ),
        ]);
    } else {
        alternatives.extend([
            discriminator_only("address"),
            discriminator_only("link"),
            discriminator_only("phone"),
            discriminator_only("organizersDefaultApp"),
            json!({ "type": "string", "minLength": 1, "deprecated": true }),
        ]);
    }
    json!({ "oneOf": alternatives })
}

fn booking_reschedule_schema() -> Value {
    let schema = object_schema(
        &["booking_uid", "start"],
        json!({
            "booking_uid": { "type": "string", "minLength": 1 },
            "start": { "type": "string", "format": "date-time" },
            "rescheduledBy": { "type": "string", "format": "email" },
            "reschedulingReason": { "type": "string" },
            "seatUid": { "type": "string", "minLength": 1 },
            "emailVerificationCode": { "type": "string" }
        }),
        false,
    );
    with_one_of(
        schema,
        json!([
            { "not": { "required": ["seatUid"] } },
            {
                "required": ["seatUid"],
                "not": { "required": ["reschedulingReason"] }
            }
        ]),
    )
}

fn booking_cancel_schema() -> Value {
    let schema = object_schema(
        &["booking_uid"],
        json!({
            "booking_uid": { "type": "string", "minLength": 1 },
            "cancellationReason": { "type": "string" },
            "cancelSubsequentBookings": { "type": "boolean" },
            "seatUid": { "type": "string", "minLength": 1 }
        }),
        false,
    );
    with_one_of(
        schema,
        json!([
            { "not": { "required": ["seatUid"] } },
            {
                "required": ["seatUid"],
                "not": { "required": ["cancelSubsequentBookings"] }
            }
        ]),
    )
}

fn booking_decline_schema() -> Value {
    object_schema(
        &["booking_uid"],
        json!({
            "booking_uid": { "type": "string", "minLength": 1 },
            "reason": { "type": "string" }
        }),
        false,
    )
}

fn booking_mark_absent_schema() -> Value {
    object_schema(
        &["booking_uid"],
        json!({
            "booking_uid": { "type": "string", "minLength": 1 },
            "host": { "type": "boolean" },
            "attendees": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "required": ["email", "absent"],
                    "properties": {
                        "email": { "type": "string", "format": "email" },
                        "absent": { "type": "boolean" }
                    },
                    "additionalProperties": false
                }
            }
        }),
        false,
    )
}

fn booking_location_update_schema() -> Value {
    object_schema(
        &["booking_uid"],
        json!({
            "booking_uid": { "type": "string", "minLength": 1 },
            "location": booking_location_schema(true)
        }),
        false,
    )
}

fn booking_attendee_add_schema() -> Value {
    let attendee = booking_attendee_schema(true);
    let mut properties = attendee
        .get("properties")
        .cloned()
        .map(object_properties)
        .unwrap_or_default();
    properties.insert(
        "booking_uid".to_owned(),
        json!({ "type": "string", "minLength": 1 }),
    );
    object_schema(
        &["booking_uid", "name", "timeZone", "email"],
        Value::Object(properties),
        false,
    )
}

fn booking_guest_add_schema() -> Value {
    object_schema(
        &["booking_uid", "guests"],
        json!({
            "booking_uid": { "type": "string", "minLength": 1 },
            "guests": {
                "type": "array",
                "minItems": 1,
                "maxItems": 10,
                "items": {
                    "type": "object",
                    "required": ["email"],
                    "properties": {
                        "email": { "type": "string", "format": "email" },
                        "name": { "type": "string" },
                        "timeZone": { "type": "string" },
                        "phoneNumber": { "type": "string", "pattern": "^\\+[1-9][0-9]{6,14}$" },
                        "language": { "type": "string", "enum": CAL_DIY_LOCALES }
                    },
                    "additionalProperties": false
                }
            }
        }),
        false,
    )
}

fn booking_reference_list_schema() -> Value {
    object_schema(
        &["booking_uid"],
        json!({
            "booking_uid": { "type": "string", "minLength": 1 },
            "type": {
                "type": "string",
                "enum": [
                    "google_calendar", "office365_calendar", "daily_video", "google_video",
                    "office365_video", "zoom_video"
                ]
            }
        }),
        false,
    )
}

fn calendar_event_create_properties(extra: Value, include_calendar_id: bool) -> Value {
    let date_time = || {
        json!({
            "type": "object",
            "required": ["time", "timeZone"],
            "properties": {
                "time": { "type": "string", "format": "date-time" },
                "timeZone": { "type": "string", "minLength": 1 }
            },
            "additionalProperties": false
        })
    };
    let mut properties = object_properties(extra);
    properties.extend(object_properties(json!({
        "title": { "type": "string", "minLength": 1 },
        "start": date_time(),
        "end": date_time(),
        "description": { "type": ["string", "null"] },
        "attendees": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["email"],
                "properties": {
                    "email": { "type": "string", "format": "email" },
                    "name": { "type": "string" }
                },
                "additionalProperties": false
            }
        }
    })));
    if include_calendar_id {
        properties.insert(
            "calendarId".to_owned(),
            json!({ "type": "string", "minLength": 1 }),
        );
    }
    Value::Object(properties)
}

fn calendar_event_update_properties(extra: Value) -> Value {
    let date_time = || {
        json!({
            "type": "object",
            "properties": {
                "time": { "type": "string", "format": "date-time" },
                "timeZone": { "type": "string" }
            },
            "additionalProperties": false
        })
    };
    let mut properties = object_properties(extra);
    properties.extend(object_properties(json!({
        "title": { "type": "string" },
        "start": date_time(),
        "end": date_time(),
        "description": { "type": ["string", "null"] },
        "attendees": {
            "type": ["array", "null"],
            "items": {
                "type": "object",
                "required": ["email"],
                "properties": {
                    "email": { "type": "string", "format": "email" },
                    "name": { "type": "string" },
                    "responseStatus": {
                        "type": ["string", "null"],
                        "enum": ["accepted", "pending", "declined", "needsAction", null]
                    },
                    "self": { "type": "boolean" },
                    "optional": { "type": "boolean" },
                    "host": { "type": "boolean" }
                },
                "additionalProperties": false
            }
        },
        "status": {
            "type": ["string", "null"],
            "enum": ["accepted", "pending", "declined", "cancelled", null]
        }
    })));
    Value::Object(properties)
}

fn schedule_properties() -> Value {
    let time = json!({ "type": "string", "pattern": "^(?:[01][0-9]|2[0-3]):[0-5][0-9]$" });
    json!({
        "name": { "type": "string", "minLength": 1 },
        "timeZone": { "type": "string", "minLength": 1 },
        "isDefault": { "type": "boolean" },
        "availability": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["days", "startTime", "endTime"],
                "properties": {
                    "days": {
                        "type": "array",
                        "minItems": 1,
                        "uniqueItems": true,
                        "items": { "type": "string", "enum": WEEK_DAYS }
                    },
                    "startTime": time,
                    "endTime": time
                },
                "additionalProperties": false
            }
        },
        "overrides": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["date", "startTime", "endTime"],
                "properties": {
                    "date": { "type": "string", "format": "date" },
                    "startTime": time,
                    "endTime": time
                },
                "additionalProperties": false
            }
        }
    })
}

fn schedule_create_schema() -> Value {
    object_schema(
        &["name", "timeZone", "isDefault"],
        schedule_properties(),
        false,
    )
}

fn schedule_update_schema() -> Value {
    let mut properties = object_properties(schedule_properties());
    properties.insert(
        "schedule_id".to_owned(),
        json!({ "type": ["string", "integer"] }),
    );
    object_schema(&["schedule_id"], Value::Object(properties), false)
}

fn with_one_of(mut schema: Value, alternatives: Value) -> Value {
    if let Some(object) = schema.as_object_mut() {
        object.insert("oneOf".to_owned(), alternatives);
    }
    schema
}

fn empty_schema() -> Value {
    object_schema(&[], json!({}), false)
}

fn object_schema(required: &[&str], properties: Value, additional_properties: bool) -> Value {
    json!({
        "type": "object",
        "required": required,
        "properties": properties,
        "additionalProperties": additional_properties
    })
}

fn object_properties(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(properties) => properties,
        _ => {
            debug_assert!(false, "internal schema properties must be an object");
            Map::new()
        }
    }
}
