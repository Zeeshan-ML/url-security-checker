document.addEventListener("DOMContentLoaded", () => {
  // Cache DOM elements
  const modal = document.getElementById("PhishingDetailsModal");
  const closeBtn = modal.querySelector(".close");
  const secureImg = document.getElementById("secureImg");
  const dangerImg = document.getElementById("dangerImg");
  const targetURLEl = document.getElementById("targetURL");
  const detailsSection = document.getElementById("details-section");
  const safeSection = document.getElementById("safeSection");

  const submissionDetailsURLEl = document.getElementById("submissionDetailsURL");
  console.log(submissionDetailsURLEl)
  const form = document.getElementById("urlForm");
   // 2. Create the new <div> element and add the "details-item" class
   const behaviorDiv = document.createElement("div");
   behaviorDiv.classList.add("details-item");
 
   // 3. Create the new <a> element and set its properties
   const behaviorLink = document.createElement("a");
   behaviorLink.href = "urlbehavior.html";
   behaviorLink.target = "_blank";
   behaviorLink.classList.add("url-info-btn");
   behaviorLink.id = "viewBehaviorBtn";
   behaviorLink.textContent = "View URL Behavior";
 
   // 4. Append the <a> element to the <div>
   behaviorDiv.appendChild(behaviorLink);
 
   // 5. Append the new <div> to the parent container
   detailsSection.appendChild(behaviorDiv);
   console.log(behaviorLink)
  // Utility: Get current date/time formatted as "yyyy/MM/dd HH:mm:ss"
  function getCurrentFormattedTime() {
    const dateObj = new Date();
    const year = dateObj.getFullYear();
    const month = ("0" + (dateObj.getMonth() + 1)).slice(-2);
    const day = ("0" + dateObj.getDate()).slice(-2);
    const hour = ("0" + dateObj.getHours()).slice(-2);
    const minute = ("0" + dateObj.getMinutes()).slice(-2);
    const second = ("0" + dateObj.getSeconds()).slice(-2);
    return `${year}/${month}/${day} ${hour}:${minute}:${second}`;
  }

  async function performAnalysis(urlToAnalyze) {
    // Reset UI from any previous analysis
    detailsSection.classList.add("d-none");
    safeSection.classList.add("d-none");
    secureImg.style.display = "none";
    dangerImg.style.display = "none";
    submissionDetailsURLEl.onclick = null;
    if (behaviorLink) behaviorLink.onclick = null;
    targetURLEl.textContent = `Analyzing ${urlToAnalyze}...`;

    try {
      // ----- Step 1: Call /analyze (which includes database check) -----
      const analyzeResponse = await fetch("/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: urlToAnalyze }),
      });
      if (!analyzeResponse.ok) {
        throw new Error("Analysis endpoint failed.");
      }
      const externalData = await analyzeResponse.json();
      console.log("Analysis Data:", externalData);

      // Check if URL is already in the database (whitelisted or blacklisted)
      if (
        typeof externalData.details === "string" &&
        (externalData.details === "Whitelisted URL" || externalData.details === "Blacklisted URL")
      ) {
        // URL exists in the database; update UI and exit.
        // submissionTimeEl.textContent = getCurrentFormattedTime();
        if (externalData.details === "Blacklisted URL") {
          dangerImg.style.display = "block";
          secureImg.style.display = "none";
          targetURLEl.textContent = "Result: Malicious(Blacklisted)";
          safeSection.textContent = "🚨 Phishing threat detected! This URL appears to be unsafe.";
          // submissionTargetEl.textContent = `Risk Level: ${externalData.riskLevel}`;
        } else if (externalData.details === "Whitelisted URL") {
          secureImg.style.display = "block";
          dangerImg.style.display = "none";
          targetURLEl.textContent = "Result: Safe(Whitelisted)";
          safeSection.textContent = "✅ No phishing threats detected. This URL seems secure.";
          // submissionTargetEl.textContent = `Risk Level: ${externalData.riskLevel}`;
        }
        safeSection.classList.remove("d-none");
        return; // Do not call any additional endpoints.
      }

      // ----- Step 2: Call /analyze-behavior for behavioral analysis -----
      let behaviorData = {};
      try {
        const behaviorResponse = await fetch("/analyze-behavior", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: urlToAnalyze }),
        });
        if (behaviorResponse.ok) {
          behaviorData = await behaviorResponse.json();
        } else {
          console.error("Behavior analysis endpoint returned an error");
          behaviorData = { eventData: {}, riskScore: "N/A" };
        }
      } catch (err) {
        console.error("Error during behavioral analysis:", err);
        behaviorData = { eventData: {}, riskScore: "N/A" };
      }
      console.log("Behavior Analysis Data:", behaviorData);

      // Convert boolean for rightClickBlocked if needed
      if (
        behaviorData.eventData &&
        typeof behaviorData.eventData.rightClickBlocked === "boolean"
      ) {
        behaviorData.eventData.rightClickBlocked = behaviorData.eventData.rightClickBlocked ? 1 : 0;
      }

      // ----- Step 3: Call /predict for ML prediction -----
      const mlPayload = {
        url: urlToAnalyze,
        nb_redirection: behaviorData.eventData.redirects || 0,
        onmouseover: behaviorData.eventData.mouseHoverCount || 0,
        right_clic: behaviorData.eventData.rightClickBlocked || 0,
        iframe: behaviorData.eventData.iframeCount || 0,
        popup_window: behaviorData.eventData.popups || 0
      };
      console.log("ML Payload:", mlPayload);

      let mlData;
      try {
        const mlResponse = await fetch("http://127.0.0.1:7000/predict", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(mlPayload),
        });
        if (!mlResponse.ok) {
          throw new Error("ML prediction endpoint failed.");
        }
        mlData = await mlResponse.json();
        console.log("ML Prediction Data:", mlData);
      } catch (error) {
        console.error("Error in ML prediction:", error);
        alert("An error occurred during ML prediction: " + error.message);
        return;
      }
      // Expected mlData.classification: "Safe", "Malicious", or "Inconclusive"
      const mlClassification = mlData.prediction;
      const externalClassification = externalData.result; // expected "Safe" or "Malicious"

      // ----- Step 4: Final Result Determination -----
      let finalClassification = "";
      if (mlClassification === "Inconclusive") {
        finalClassification = "Further investigation needed";
        alert("The ML result is inconclusive. This URL requires further review!");
      } else if (mlClassification === externalClassification) {
        // Both sources agree.
        finalClassification = mlClassification;
      } else {
        // Discrepancy found: further investigation is needed.
        finalClassification = "Further investigation needed";
        // Save external and behavioral data for later review in details pages.
        sessionStorage.setItem("analysisData", JSON.stringify(externalData));
        sessionStorage.setItem("behaviorData", JSON.stringify(behaviorData));
      }

      // ----- Step 5: Update UI with Full Analysis Details -----
      // submissionTimeEl.textContent = getCurrentFormattedTime();
      // detailsSection.innerHTML = "";
      // const header = document.createElement("h3");
      // header.textContent = "URL Analysis Details";
      // detailsSection.appendChild(header);

      // External Analysis Details
      // const externalResultsDiv = document.createElement("div");
      // externalResultsDiv.innerHTML = `<h4>External Security Services Results</h4>`;
      // const externalList = document.createElement("ul");
      // if (Array.isArray(externalData.details)) {
      //   externalData.details.forEach(detail => {
      //     const li = document.createElement("li");
      //     li.textContent = detail;
      //     externalList.appendChild(li);
      //   });
      // } else {
      //   const li = document.createElement("li");
      //   li.textContent = externalData.details || "No details available.";
      //   externalList.appendChild(li);
      // }
      // externalResultsDiv.appendChild(externalList);
      // externalResultsDiv.innerHTML += `<p><strong>Overall Risk Level:</strong> ${externalData.riskLevel || "Unknown"}</p>`;
      // detailsSection.appendChild(externalResultsDiv);

      // Behavioral Analysis Details
      // const behaviorAnalysisDiv = document.createElement("div");
      // behaviorAnalysisDiv.innerHTML = `<h4>Behavioral Analysis</h4>`;
      // const behaviorList = document.createElement("ul");
      // const ed = behaviorData.eventData || {};
      // behaviorList.innerHTML = `
      //   <li>Redirects: ${ed.redirects || 0}</li>
      //   <li>Mouse Hover Count: ${ed.mouseHoverCount || 0}</li>
      //   <li>Time Spent: ${ed.timeSpent ? ed.timeSpent + " ms" : "N/A"}</li>
      //   <li>Right-click Blocked: ${ed.rightClickBlocked ? "Yes" : "No"}</li>
      //   <li>IFrame Count: ${ed.iframeCount || 0}</li>
      //   <li>Pop-ups: ${ed.popups || 0}</li>
      //   <li>Auto Form Submissions: ${ed.autoFormSubmissions || 0}</li>
      //   <li>Keystroke Listeners: ${ed.keystrokeListeners || 0}</li>
      //   <li>Clipboard Access: ${ed.clipboardAccess ? "Yes" : "No"}</li>
      //   <li>Obfuscated Links: ${ed.obfuscatedLinks || 0}</li>
      // `;
      // behaviorAnalysisDiv.appendChild(behaviorList);
      // behaviorAnalysisDiv.innerHTML += `<p><strong>Behavioral Risk Score:</strong> ${behaviorData.riskScore}</p>`;
      // detailsSection.appendChild(behaviorAnalysisDiv);


      // ML Prediction Details
      const mlDiv = document.createElement("div");
      mlDiv.innerHTML = `<span style="color: white; font-weight: bold;">ML Model Prediction: </span>
                        <span style="color: white; font-weight: bold;">${mlClassification}</span>`;
      detailsSection.appendChild(mlDiv);



      // Append links for further details
      submissionDetailsURLEl.classList.remove("d-none");
      submissionDetailsURLEl.textContent = "View External API Details";
      submissionDetailsURLEl.style.cursor = "pointer";
      submissionDetailsURLEl.onclick = (e) => {
        e.preventDefault();
        sessionStorage.setItem("analysisData", JSON.stringify(externalData));
        window.open("details.html", "_blank");
      };
      detailsSection.appendChild(submissionDetailsURLEl);
      if (behaviorLink) {

        behaviorLink.classList.remove("d-none");
        behaviorLink.textContent = "View Behavioral Analysis Details";
        behaviorLink.style.cursor = "pointer";
        behaviorLink.onclick = (e) => {
          e.preventDefault();
          sessionStorage.setItem("behaviorData", JSON.stringify(behaviorData));
          window.open("urlbehavior.html", "_blank");
        };
        detailsSection.appendChild(behaviorLink);
      }

      // Display the final result
      if (finalClassification === "Malicious") {
        dangerImg.style.display = "block";
        secureImg.style.display = "none";
        targetURLEl.textContent = "Result: Malicious";
        safeSection.textContent = "🚨 Phishing threat detected! This URL appears to be unsafe.";
        safeSection.classList.remove("d-none");
        // submissionTargetEl.textContent = `Risk Level: ${externalData.riskLevel || "Unknown"}`;
        detailsSection.classList.remove("d-none");
      } else if (finalClassification === "Safe") {
        secureImg.style.display = "block";
        dangerImg.style.display = "none";
        targetURLEl.textContent = "Result: Safe";
        safeSection.textContent = "✅ No phishing threats detected. This URL seems secure.";
        safeSection.classList.remove("d-none");
        detailsSection.classList.remove("d-none");
      } else {
        targetURLEl.textContent = "Result: Further Investigation Needed";
        const discrepancyDiv = document.createElement("div");
        discrepancyDiv.innerHTML = `<p>The ML prediction does not match the external analysis. Please review the details below:</p>`;
        detailsSection.insertBefore(discrepancyDiv, detailsSection.firstChild);
        detailsSection.classList.remove("d-none");
      }
    } catch (error) {
      console.error("Error:", error);
      alert("An error occurred: " + error.message);
    }
  }

  // --- Modal Closing Logic ---
  closeBtn.addEventListener("click", () => {
    modal.style.display = "none";
  });

  window.addEventListener("click", (event) => {
    if (event.target === modal) {
      modal.style.display = "none";
    }
  });

  // --- Form Submission Handler ---
  if (form) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      modal.style.display = "block";
      const urlToAnalyze = form.elements.url.value;
      performAnalysis(urlToAnalyze);
    });
  } else {
    // If no form exists, try to get the URL from query parameters.
    const params = new URLSearchParams(window.location.search);
    const urlParam = params.get("url");
    if (urlParam) {
      modal.style.display = "block";
      performAnalysis(urlParam);
    } else {
      targetURLEl.textContent = "No URL provided.";
    }
  }
});
