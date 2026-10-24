// ============================================================
// CONFIGURATION
// ============================================================

const API_BASE = "";

let currentTrafficType = "suspicious";

let monitoringActive = false;

let monitoringInterval = null;

let trafficChart = null;

let anomalyChart = null;


// ============================================================
// INITIALIZATION
// ============================================================

document.addEventListener(
    "DOMContentLoaded",
    () => {

        initializeCharts();

        checkBackend();

        loadDashboard();

        loadIncidents();

        addLog(
            "Dashboard initialized.",
            "success"
        );

    }
);


// ============================================================
// BACKEND STATUS
// ============================================================

async function checkBackend() {

    try {

        const response = await fetch(
            `${API_BASE}/api/status`
        );

        if (!response.ok) {
            throw new Error(
                "Backend unavailable"
            );
        }

        const data =
            await response.json();

        setBackendOnline();

        addLog(
            "Backend connection established.",
            "success"
        );

    } catch (error) {

        setBackendOffline();

        addLog(
            "Backend connection failed.",
            "error"
        );

    }

}


function setBackendOnline() {

    const dot =
        document.getElementById(
            "systemDot"
        );

    const status =
        document.getElementById(
            "systemStatus"
        );

    dot.style.background =
        "#52d98a";

    status.textContent =
        "BACKEND ONLINE";

    status.style.color =
        "#8ee0b1";

}


function setBackendOffline() {

    const dot =
        document.getElementById(
            "systemDot"
        );

    const status =
        document.getElementById(
            "systemStatus"
        );

    dot.style.background =
        "#ef6874";

    status.textContent =
        "BACKEND OFFLINE";

    status.style.color =
        "#ef8791";

}


// ============================================================
// TRAFFIC TYPE
// ============================================================

document.addEventListener(
    "change",
    function (event) {

        if (
            event.target.id ===
            "trafficTypeSelect"
        ) {

            currentTrafficType =
                event.target.value;

            analyzeSelectedTraffic();

        }

    }
);


// ============================================================
// ANALYZE
// ============================================================

async function analyzeSelectedTraffic() {

    const selector =
        document.getElementById(
            "trafficTypeSelect"
        );

    currentTrafficType =
        selector.value;

    await loadDashboard();

}


// ============================================================
// LOAD DASHBOARD
// ============================================================

async function loadDashboard() {

    try {

        const response =
            await fetch(
                `${API_BASE}/api/analyze?type=${currentTrafficType}`
            );

        if (!response.ok) {

            throw new Error(
                "Analysis request failed"
            );

        }

        const data =
            await response.json();

        updateDashboard(data);

        setBackendOnline();

        addLog(
            "Dashboard data updated successfully.",
            "success"
        );

    } catch (error) {

        addLog(
            `Dashboard update failed: ${error.message}`,
            "error"
        );

        setBackendOffline();

    }

}


// ============================================================
// UPDATE DASHBOARD
// ============================================================

function updateDashboard(data) {

    const score =
        Number(data.anomaly_score || 0);

    const severity =
        data.severity || "--";

    const threat =
        data.threat_type || "--";

    const confidence =
        data.confidence || "--";


    // ----------------------------------------
    // MAIN CARDS
    // ----------------------------------------

    document.getElementById(
        "anomalyScore"
    ).textContent =
        score.toFixed(2);


    document.getElementById(
        "severity"
    ).textContent =
        severity;


    document.getElementById(
        "threatType"
    ).textContent =
        threat;


    document.getElementById(
        "confidence"
    ).textContent =
        confidence;


    // ----------------------------------------
    // SEVERITY CLASS
    // ----------------------------------------

    updateSeverityStyle(
        document.getElementById(
            "severity"
        ),
        severity
    );


    // ----------------------------------------
    // ALERT
    // ----------------------------------------

    updateAlertBanner(
        severity,
        threat
    );


    // ----------------------------------------
    // FEATURES
    // ----------------------------------------

    if (
        data.current_features &&
        data.baseline_features
    ) {

        updateMetrics(
            data.current_features
        );

        updateComparison(
            data.current_features,
            data.baseline_features
        );

        updateCharts(
            data.current_features,
            data.baseline_features
        );

        updateCaptureInformation(
            data.current_features
        );

    }


    // ----------------------------------------
    // DETECTION REASONS
    // ----------------------------------------

    updateReasons(
        data.reasons || []
    );


    // ----------------------------------------
    // TIMESTAMP
    // ----------------------------------------

    updateLastUpdated();


    document.getElementById(
        "analysisStatus"
    ).textContent =
        "COMPLETED";

}


// ============================================================
// ALERT BANNER
// ============================================================

function updateAlertBanner(
    severity,
    threat
) {

    const banner =
        document.getElementById(
            "alertBanner"
        );

    const title =
        document.getElementById(
            "alertTitle"
        );

    const message =
        document.getElementById(
            "alertMessage"
        );

    const severityBox =
        document.getElementById(
            "alertSeverity"
        );


    if (
        severity === "HIGH" ||
        severity === "MEDIUM"
    ) {

        banner.classList.remove(
            "hidden"
        );

        title.textContent =
            "ACTIVE SECURITY ALERT";

        message.textContent =
            `${threat} detected in analyzed traffic.`;

        severityBox.textContent =
            severity;

    } else {

        banner.classList.add(
            "hidden"
        );

    }

}


// ============================================================
// SEVERITY STYLE
// ============================================================

function updateSeverityStyle(
    element,
    severity
) {

    element.classList.remove(
        "severity-high",
        "severity-medium",
        "severity-low"
    );

    if (severity === "HIGH") {

        element.classList.add(
            "severity-high"
        );

    } else if (severity === "MEDIUM") {

        element.classList.add(
            "severity-medium"
        );

    } else {

        element.classList.add(
            "severity-low"
        );

    }

}


// ============================================================
// METRICS
// ============================================================

function updateMetrics(features) {

    document.getElementById(
        "m_pkts"
    ).textContent =
        formatNumber(
            features.total_packets
        );


    document.getElementById(
        "m_proto"
    ).textContent =
        `${formatNumber(features.tcp_packets)} / ` +
        `${formatNumber(features.udp_packets)} / ` +
        `${formatNumber(features.icmp_packets)}`;


    document.getElementById(
        "m_syn"
    ).textContent =
        formatNumber(
            features.syn_packets
        );


    document.getElementById(
        "m_ips"
    ).textContent =
        `${formatNumber(features.unique_source_ips)} / ` +
        `${formatNumber(features.unique_destination_ips)}`;


    document.getElementById(
        "m_ports"
    ).textContent =
        formatNumber(
            features.unique_destination_ports
        );


    document.getElementById(
        "m_size"
    ).textContent =
        `${formatNumber(features.average_packet_size)} B`;


    document.getElementById(
        "m_pps"
    ).textContent =
        formatNumber(
            features.packets_per_second
        );


    document.getElementById(
        "m_rst"
    ).textContent =
        formatNumber(
            features.rst_packets
        );

}


// ============================================================
// BASELINE COMPARISON
// ============================================================

function updateComparison(
    current,
    baseline
) {

    updateComparisonItem(
        "pps",
        current.packets_per_second,
        baseline.packets_per_second
    );

    updateComparisonItem(
        "syn",
        current.syn_packets,
        baseline.syn_packets
    );

    updateComparisonItem(
        "ports",
        current.unique_destination_ports,
        baseline.unique_destination_ports
    );

    updateComparisonItem(
        "size",
        current.average_packet_size,
        baseline.average_packet_size
    );

}


function updateComparisonItem(
    name,
    current,
    baseline
) {

    current =
        Number(current || 0);

    baseline =
        Number(baseline || 0);


    const currentElement =
        document.getElementById(
            `cmp_${name}_current`
        );

    const baselineElement =
        document.getElementById(
            `cmp_${name}_baseline`
        );

    const changeElement =
        document.getElementById(
            `cmp_${name}_change`
        );


    currentElement.textContent =
        formatNumber(current);


    baselineElement.textContent =
        `Baseline: ${formatNumber(baseline)}`;


    if (baseline === 0) {

        if (current === 0) {

            changeElement.textContent =
                "No change";

        } else {

            changeElement.textContent =
                "Increase from zero baseline";

        }

        return;

    }


    const percentage =
        ((current - baseline) /
            Math.abs(baseline)) *
        100;


    const sign =
        percentage >= 0
            ? "+"
            : "";


    changeElement.textContent =
        `${sign}${percentage.toFixed(2)}%`;

}


// ============================================================
// CAPTURE INFORMATION
// ============================================================

function updateCaptureInformation(
    features
) {

    let fileName;

    if (
        currentTrafficType ===
        "suspicious"
    ) {

        fileName =
            "suspicious_traffic.pcapng";

    } else {

        fileName =
            "normal_kali_test.pcapng";

    }


    document.getElementById(
        "captureFile"
    ).textContent =
        fileName;


    document.getElementById(
        "capturePackets"
    ).textContent =
        formatNumber(
            features.total_packets
        );


    document.getElementById(
        "captureDuration"
    ).textContent =
        `${formatNumber(features.duration)} sec`;

}


// ============================================================
// DETECTION REASONS
// ============================================================

function updateReasons(reasons) {

    const container =
        document.getElementById(
            "reasonsContainer"
        );


    if (!reasons || reasons.length === 0) {

        container.innerHTML = `
            <div class="no-reason">
                No significant anomalies detected.
            </div>
        `;

        return;

    }


    container.innerHTML = "";


    reasons.forEach(
        reason => {

            const item =
                document.createElement(
                    "div"
                );

            item.className =
                "reason-item";


            item.innerHTML = `

                <div class="reason-icon">
                    !
                </div>

                <span>
                    ${escapeHtml(reason)}
                </span>

            `;


            container.appendChild(
                item
            );

        }
    );

}


// ============================================================
// CHARTS
// ============================================================

function initializeCharts() {

    const trafficCanvas =
        document.getElementById(
            "trafficChart"
        );

    const anomalyCanvas =
        document.getElementById(
            "anomalyChart"
        );


    trafficChart =
        new Chart(
            trafficCanvas,
            {

                type: "doughnut",

                data: {

                    labels: [
                        "TCP",
                        "UDP",
                        "ICMP"
                    ],

                    datasets: [

                        {

                            data: [
                                0,
                                0,
                                0
                            ]

                        }

                    ]

                },

                options: {

                    responsive: true,

                    maintainAspectRatio:
                        false,

                    plugins: {

                        legend: {

                            labels: {

                                color:
                                    "#aab7c8",

                                font: {

                                    size: 11

                                }

                            }

                        }

                    }

                }

            }
        );


    anomalyChart =
        new Chart(
            anomalyCanvas,
            {

                type: "bar",

                data: {

                    labels: [
                        "Packets/s",
                        "SYN",
                        "Dst Ports",
                        "Packet Size"
                    ],

                    datasets: [

                        {

                            label:
                                "Baseline",

                            data: [
                                0,
                                0,
                                0,
                                0
                            ]

                        },

                        {

                            label:
                                "Current",

                            data: [
                                0,
                                0,
                                0,
                                0
                            ]

                        }

                    ]

                },

                options: {

                    responsive: true,

                    maintainAspectRatio:
                        false,

                    scales: {

                        x: {

                            ticks: {

                                color:
                                    "#8795a8",

                                font: {

                                    size: 10

                                }

                            },

                            grid: {

                                color:
                                    "#182332"

                            }

                        },

                        y: {

                            beginAtZero: true,

                            ticks: {

                                color:
                                    "#8795a8",

                                font: {

                                    size: 10

                                }

                            },

                            grid: {

                                color:
                                    "#182332"

                            }

                        }

                    },

                    plugins: {

                        legend: {

                            labels: {

                                color:
                                    "#aab7c8",

                                font: {

                                    size: 11

                                }

                            }

                        }

                    }

                }

            }
        );

}


// ============================================================
// UPDATE CHARTS
// ============================================================

function updateCharts(
    current,
    baseline
) {

    if (!trafficChart ||
        !anomalyChart) {

        return;

    }


    trafficChart.data.datasets[0].data = [

        Number(current.tcp_packets || 0),

        Number(current.udp_packets || 0),

        Number(current.icmp_packets || 0)

    ];

    trafficChart.update();


    anomalyChart.data.datasets[0].data = [

        Number(
            baseline.packets_per_second || 0
        ),

        Number(
            baseline.syn_packets || 0
        ),

        Number(
            baseline.unique_destination_ports || 0
        ),

        Number(
            baseline.average_packet_size || 0
        )

    ];


    anomalyChart.data.datasets[1].data = [

        Number(
            current.packets_per_second || 0
        ),

        Number(
            current.syn_packets || 0
        ),

        Number(
            current.unique_destination_ports || 0
        ),

        Number(
            current.average_packet_size || 0
        )

    ];


    anomalyChart.update();

}


// ============================================================
// INCIDENTS
// ============================================================

async function loadIncidents() {

    try {

        const response =
            await fetch(
                `${API_BASE}/api/incidents`
            );


        if (!response.ok) {

            throw new Error(
                "Could not load incidents"
            );

        }


        const incidents =
            await response.json();


        updateIncidentTable(
            incidents
        );


        updateIncidentCounters(
            incidents
        );


    } catch (error) {

        addLog(
            `Incident loading failed: ${error.message}`,
            "error"
        );

    }

}


// ============================================================
// INCIDENT TABLE
// ============================================================

function updateIncidentTable(
    incidents
) {

    const table =
        document.getElementById(
            "incidentTable"
        );


    table.innerHTML = "";


    if (
        !Array.isArray(incidents) ||
        incidents.length === 0
    ) {

        table.innerHTML = `

            <tr>

                <td colspan="6">
                    No incidents recorded.
                </td>

            </tr>

        `;

        return;

    }


    incidents
        .slice()
        .reverse()
        .forEach(
            incident => {

                const row =
                    document.createElement(
                        "tr"
                    );


                const severity =
                    String(
                        incident.severity || ""
                    ).toUpperCase();


                const status =
                    String(
                        incident.status || ""
                    ).toUpperCase();


                row.innerHTML = `

                    <td>
                        ${escapeHtml(
                            incident.incident_id ||
                            incident.id ||
                            "--"
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            incident.threat_type ||
                            incident.threat ||
                            "--"
                        )}
                    </td>

                    <td class="${getSeverityClass(severity)}">
                        ${escapeHtml(severity)}
                    </td>

                    <td>
                        ${formatNumber(
                            incident.anomaly_score ||
                            incident.score ||
                            0
                        )}
                    </td>

                    <td class="${getStatusClass(status)}">
                        ${escapeHtml(status)}
                    </td>

                    <td>
                        ${escapeHtml(
                            getEvidenceName(
                                incident.evidence ||
                                incident.evidence_path ||
                                ""
                            )
                        )}
                    </td>

                `;


                table.appendChild(
                    row
                );

            }
        );

}


// ============================================================
// INCIDENT COUNTERS
// ============================================================

function updateIncidentCounters(
    incidents
) {

    const total =
        Array.isArray(incidents)
            ? incidents.length
            : 0;


    const active =
        Array.isArray(incidents)
            ? incidents.filter(
                incident =>
                    String(
                        incident.status || ""
                    ).toUpperCase()
                    === "OPEN"
            ).length
            : 0;


    document.getElementById(
        "totalIncidents"
    ).textContent =
        total;


    document.getElementById(
        "activeIncidents"
    ).textContent =
        active;


    document.getElementById(
        "evidenceStatus"
    ).textContent =
        total > 0
            ? "AVAILABLE"
            : "READY";

}


// ============================================================
// MONITORING
// ============================================================

function toggleLiveMonitoring() {

    const button =
        document.getElementById(
            "liveBtn"
        );

    const banner =
        document.getElementById(
            "liveBannerStatus"
        );


    if (!monitoringActive) {

        monitoringActive =
            true;


        button.textContent =
            "Stop Monitoring";


        banner.textContent =
            "● MONITORING ACTIVE";


        addLog(
            "Monitoring started.",
            "success"
        );


        loadDashboard();

        loadIncidents();


        monitoringInterval =
            setInterval(
                () => {

                    loadDashboard();

                    loadIncidents();

                },
                5000
            );


    } else {

        monitoringActive =
            false;


        button.textContent =
            "Start Monitoring";


        banner.textContent =
            "● ANALYSIS READY";


        clearInterval(
            monitoringInterval
        );


        addLog(
            "Monitoring stopped.",
            "success"
        );

    }

}


// ============================================================
// LOGGING
// ============================================================

function addLog(
    message,
    type = ""
) {

    const container =
        document.getElementById(
            "activityLog"
        );


    if (!container) {
        return;
    }


    const empty =
        container.querySelector(
            ".no-reason"
        );


    if (empty) {
        empty.remove();
    }


    const entry =
        document.createElement(
            "div"
        );


    entry.className =
        `log-entry ${type}`;


    const now =
        new Date();


    const time =
        now.toLocaleTimeString();


    entry.textContent =
        `[${time}] ${message}`;


    container.prepend(
        entry
    );


    while (
        container.children.length > 30
    ) {

        container.removeChild(
            container.lastChild
        );

    }

}


// ============================================================
// LAST UPDATED
// ============================================================

function updateLastUpdated() {

    const now =
        new Date();


    document.getElementById(
        "lastUpdated"
    ).textContent =
        now.toLocaleTimeString();

}


// ============================================================
// UTILITY FUNCTIONS
// ============================================================

function formatNumber(
    value
) {

    const number =
        Number(value);


    if (!Number.isFinite(number)) {
        return "0";
    }


    return number.toLocaleString(
        undefined,
        {
            maximumFractionDigits: 2
        }
    );

}


function getSeverityClass(
    severity
) {

    if (severity === "HIGH") {
        return "severity-high";
    }

    if (severity === "MEDIUM") {
        return "severity-medium";
    }

    return "severity-low";

}


function getStatusClass(
    status
) {

    if (status === "OPEN") {
        return "status-open";
    }

    return "status-closed";

}


function getEvidenceName(
    path
) {

    if (!path) {
        return "--";
    }

    const parts =
        path.split(
            /[\\/]/
        );

    return parts[
        parts.length - 1
    ];

}


function escapeHtml(
    text
) {

    const div =
        document.createElement(
            "div"
        );

    div.textContent =
        String(text);

    return div.innerHTML;

}