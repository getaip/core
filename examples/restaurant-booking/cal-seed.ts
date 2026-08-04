import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

import prisma from "@calcom/prisma";

const USER_ID = 70001;
const SCHEDULE_ID = 70001;
const AVAILABILITY_ID = 70001;
const EVENT_TYPE_ID = 70001;
const API_KEY_ID = "aip-restaurant-booking-api-key";

async function main() {
  const tokenPath = process.env.CAL_API_KEY_FILE;
  if (!tokenPath) throw new Error("CAL_API_KEY_FILE is required");
  const bearer = (await readFile(tokenPath, "utf8")).trim();
  if (!bearer.startsWith("cal_") || bearer.length < 32) {
    throw new Error("Cal.diy API key has an invalid prefix or length");
  }
  const hashedKey = createHash("sha256").update(bearer.slice(4)).digest("hex");

  const user = await prisma.user.upsert({
    where: { email: "host@aip-bistro.example.test" },
    update: {
      username: "aip-bistro",
      name: "AIP Bistro",
      timeZone: "Asia/Dubai",
      completedOnboarding: true,
      emailVerified: new Date(),
    },
    create: {
      id: USER_ID,
      username: "aip-bistro",
      name: "AIP Bistro",
      email: "host@aip-bistro.example.test",
      timeZone: "Asia/Dubai",
      completedOnboarding: true,
      emailVerified: new Date(),
      locale: "en",
    },
  });

  const schedule = await prisma.schedule.upsert({
    where: { id: SCHEDULE_ID },
    update: { name: "AIP Bistro service hours", timeZone: "Asia/Dubai" },
    create: {
      id: SCHEDULE_ID,
      userId: user.id,
      name: "AIP Bistro service hours",
      timeZone: "Asia/Dubai",
    },
  });

  await prisma.availability.upsert({
    where: { id: AVAILABILITY_ID },
    update: {
      userId: user.id,
      scheduleId: schedule.id,
      days: [0, 1, 2, 3, 4, 5, 6],
      startTime: new Date("1970-01-01T00:00:00.000Z"),
      endTime: new Date("1970-01-01T23:59:00.000Z"),
    },
    create: {
      id: AVAILABILITY_ID,
      userId: user.id,
      scheduleId: schedule.id,
      days: [0, 1, 2, 3, 4, 5, 6],
      startTime: new Date("1970-01-01T00:00:00.000Z"),
      endTime: new Date("1970-01-01T23:59:00.000Z"),
    },
  });

  await prisma.user.update({
    where: { id: user.id },
    data: { defaultScheduleId: schedule.id },
  });

  await prisma.eventType.upsert({
    where: { id: EVENT_TYPE_ID },
    update: {
      title: "AIP Bistro dinner reservation",
      slug: "dinner",
      length: 90,
      minimumBookingNotice: 0,
      seatsPerTimeSlot: 8,
      timeZone: "Asia/Dubai",
      scheduleId: schedule.id,
      userId: user.id,
      users: { connect: { id: user.id } },
    },
    create: {
      id: EVENT_TYPE_ID,
      title: "AIP Bistro dinner reservation",
      slug: "dinner",
      length: 90,
      minimumBookingNotice: 0,
      seatsPerTimeSlot: 8,
      timeZone: "Asia/Dubai",
      scheduleId: schedule.id,
      userId: user.id,
      users: { connect: { id: user.id } },
    },
  });

  await prisma.apiKey.upsert({
    where: { id: API_KEY_ID },
    update: { userId: user.id, hashedKey, expiresAt: null },
    create: {
      id: API_KEY_ID,
      userId: user.id,
      note: "AIP restaurant production E2E",
      hashedKey,
      expiresAt: null,
    },
  });

  process.stdout.write(
    JSON.stringify({ status: "ready", eventTypeId: EVENT_TYPE_ID }) + "\n"
  );
}

main()
  .catch((error: unknown) => {
    const message = error instanceof Error ? error.message : "unknown seed error";
    process.stderr.write(`Cal.diy seed failed: ${message}\n`);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
    process.exit(process.exitCode ?? 0);
  });
