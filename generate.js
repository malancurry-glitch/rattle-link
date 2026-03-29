import { DynamoDBClient, PutItemCommand } from "@aws-sdk/client-dynamodb";

const client = new DynamoDBClient({ region: "us-east-2" });

const BASE_URL = "https://suvegwrmzl.execute-api.us-east-2.amazonaws.com";

// 🔹 Generate random slug
function generateSlug(length = 6) {
    const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let slug = "";
    for (let i = 0; i < length; i++) {
        slug += chars[Math.floor(Math.random() * chars.length)];
    }
    return slug;
}

// 🔹 Create link
async function createLink(url, customSlug) {
    const slug = customSlug || generateSlug();

    try {
        await client.send(new PutItemCommand({
            TableName: "redirects",
            Item: {
                slug: { S: slug },
                url: { S: url }
            },
            // ❗ Prevent duplicate slugs
            ConditionExpression: "attribute_not_exists(slug)"
        }));

        return `${BASE_URL}/${slug}`;

    } catch (err) {
        if (err.name === "ConditionalCheckFailedException") {
            throw new Error("Slug already exists. Try another custom name.");
        }

        throw err;
    }
}

// 🔹 CLI usage
const url = process.argv[2];
const customSlug = process.argv[3]; // optional

if (!url) {
    console.log("Usage:");
    console.log("  node generate.js https://example.com");
    console.log("  node generate.js https://example.com customSlug");
    process.exit(1);
}

// 🔹 Run
createLink(url, customSlug)
    .then(link => {
        console.log("✅ Short link:", link);
    })
    .catch(err => {
        console.error("❌ Error:", err.message);
    });