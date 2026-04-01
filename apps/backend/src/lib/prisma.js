import { PrismaClient } from "@prisma/client";

export const prisma = new PrismaClient({
    datasource: {
        url: process.env.DATABASE_URL,
    },
});