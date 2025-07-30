const crypto = require("crypto");
const axios = require("axios");

module.exports = async function (context, req) {
  const username = req.body?.data?.context?.user?.profile?.login;

  if (!username) {
    context.res = {
      status: 400,
      body: { error: "No username provided" }
    };
    return;
  }

  const IKEY = process.env.DUO_IKEY;
  const SKEY = process.env.DUO_SKEY;
  const HOST = process.env.DUO_API_HOSTNAME;

  const method = "GET";
  const path = "/admin/v1/users";
  const date = new Date().toUTCString();
  const params = `username=${encodeURIComponent(username)}`;
  const canon = [date, method.toUpperCase(), HOST.toLowerCase(), path, params].join("\n");

  const signature = crypto
    .createHmac("sha1", SKEY)
    .update(canon)
    .digest("hex");

  const auth = `${IKEY}:${signature}`;

  try {
    const response = await axios.get(`https://${HOST}${path}?${params}`, {
      headers: {
        Authorization: `Basic ${auth}`,
        Date: date,
      },
    });

    const duoUser = response.data?.response?.[0];
    const isEnrolled = (duoUser?.phones?.length || 0) > 0;

    context.res = {
      status: 200,
      body: isEnrolled
        ? {
            commands: [
              {
                type: "com.okta.user.profile.update",
                value: {
                  duoEnrolled: "true",
                },
              },
            ],
          }
        : {
            commands: [
              {
                type: "deny",
                value: {
                  errorSummary: "Duo enrollment is required before continuing.",
                },
              },
            ],
          },
    };
  } catch (error) {
    context.res = {
      status: 500,
      body: {
        commands: [
          {
            type: "deny",
            value: {
              errorSummary: "Unable to verify Duo enrollment.",
            },
          },
        ],
      },
    };
  }
};
