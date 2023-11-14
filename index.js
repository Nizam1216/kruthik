const express = require("express");
const bodyParser = require("body-parser");
const axios = require("axios");

const app = express();
const PORT = process.env.PORT || 3000;

// Use bodyParser middleware to parse JSON data
app.use(bodyParser.json());

// Serve static files from the "public" directory
app.use(express.static("public"));

// Function to check if the URL is valid
function isValidUrl(url) {
  const pattern = /^(http|https):\/\//;
  return pattern.test(url);
}

// Define the route for handling URL checks
app.post("/", async (req, res) => {
  try {
    // Extract the resource URL from the request body
    const resource_url = req.body.link;

    // Check if the URL is empty or missing
    if (!resource_url) {
      return res.status(400).json({ error: "No URL provided" });
    }

    // Check if the URL is valid
    if (!isValidUrl(resource_url)) {
      return res
        .status(400)
        .json({ error: 'Invalid URL. Please include "http://" or "https://"' });
    }

    // Make the request to the VirusTotal API
    const url = "https://www.virustotal.com/vtapi/v2/url/report";
    const api_key =
      "840182d355a31efde49feb02b829951d85977053f9e4b3ba1aa085446d37e52c";
    const params = { apikey: api_key, resource: resource_url };
    const response = await axios.get(url, { params });

    // Check the status code of the API response
    if (response.status === 200) {
      const json_response = response.data;

      // Check the response code from the VirusTotal API
      if (json_response.response_code === 1) {
        return res.json({ result: "URL is safe" });
      } else if (json_response.response_code === -2) {
        return res.json({ result: "URL has not been analyzed yet" });
      } else {
        return res.json({ result: "URL is malicious" });
      }
    } else {
      return res
        .status(response.status)
        .json({ error: `Error: ${response.status}` });
    }
  } catch (error) {
    console.error("Error:", error.message);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
