const state = {
  health: null,
  config: null,
  devices: [],
  profiles: [],
  pihole: null,
  busy: false,
  scanning: false,
  activeTab: "home",
  selectedIp: null,
  devicePage: null,
  deviceTimer: null,
  activityTimer: null,
  inventoryTimer: null,
  analytics: null,
  activityEvents: [],
  activityLatestId: 0,
  filters: { q: "", client: "", category: "", status: "" },
  lastInventoryAt: 0,
  historyWindow: "24h",
  history: null,
  alerts: [],
  unackedAlerts: 0,
  setup: null,
  piholeStatus: null,
  theme: "lcars",
  selectedAlertId: null,
  overview: null,
  uiMode: "simple",
  globalSearch: "",
  protectionDatabase: null,
  blocklists: [],
  accessRequests: [],
  accessRequestDeviceNames: {},
  report: null,
  systemHealth: null,
  capabilities: null,
  community: null,
  retention: null,
  security: null,
  auditEvents: [],
};

const ALERT_GUIDE = {
  new_device: {
    label: "New device",
    meaning: "A device appeared on your Wi‑Fi that Pi-Circle hadn’t seen before.",
    action: "Open the device page to label it, link it, or leave it alone if you recognize it.",
  },
  late_night: {
    label: "Late-night activity",
    meaning: "This device made a lot of DNS lookups overnight (11pm–5am).",
    action: "Check the device’s recent activity. Use bedtime or pause if it shouldn’t be online.",
  },
  spike: {
    label: "Traffic spike",
    meaning: "This device suddenly made many DNS lookups in a short window.",
    action: "Review live activity for unusual apps or downloads.",
  },
  blocked_burst: {
    label: "Blocked burst",
    meaning: "Pi-hole blocked many queries from this device in a short window.",
    action: "Normal for ad-heavy apps. If something useful broke, open Pi-hole Settings to allow a domain.",
  },
  doh_bypass: {
    label: "DNS bypass attempt",
    meaning: "The device tried to use private/encrypted DNS that can skip Pi-hole blocking.",
    action: "Turn off Private DNS / Secure DNS on the phone, or keep Privacy Shield enabled.",
  },
  telemetry: {
    label: "Telemetry contact",
    meaning: "The device contacted a known tracking/telemetry host that Privacy Shield denylists.",
    action: "Usually fine. Open the device report if you want to see what was contacted.",
  },
};

const DEVICE_TYPES = [
  ["unknown", "Unknown"],
  ["router", "Router"],
  ["iphone", "iPhone"],
  ["ipad", "iPad"],
  ["android", "Android"],
  ["pc", "PC"],
  ["laptop", "Laptop"],
  ["tv", "TV"],
  ["game", "Game"],
  ["iot", "Smart Home"],
];

const elements = {
  healthPill: document.querySelector("#health-pill"),
  overviewPanel: document.querySelector("#overview-panel"),
  overviewSummary: document.querySelector("#overview-summary"),
  overviewStatus: document.querySelector("#overview-status"),
  overviewMetrics: document.querySelector("#overview-metrics"),
  overviewChart: document.querySelector("#overview-chart"),
  overviewDevices: document.querySelector("#overview-devices"),
  overviewServices: document.querySelector("#overview-services"),
  overviewAlerts: document.querySelector("#overview-alerts"),
  servicesPanel: document.querySelector("#services-panel"),
  servicesSummary: document.querySelector("#services-summary"),
  serviceGrid: document.querySelector("#service-grid"),
  globalSearch: document.querySelector("#global-search"),
  modeToggle: document.querySelector("#mode-toggle"),
  mode: document.querySelector("#mode"),
  interfaceName: document.querySelector("#interface"),
  deviceCount: document.querySelector("#device-count"),
  targetCount: document.querySelector("#target-count"),
  adlistCount: document.querySelector("#adlist-count"),
  gravityCount: document.querySelector("#gravity-count"),
  stardate: document.querySelector("#stardate"),
  statusMessage: document.querySelector("#status-message"),
  tabs: Array.from(document.querySelectorAll("[data-tab-target]")),
  homePanel: document.querySelector("#home-panel"),
  activityPanel: document.querySelector("#activity-panel"),
  devicePage: document.querySelector("#device-page"),
  controlsPanel: document.querySelector("#controls-panel"),
  dnsPanel: document.querySelector("#dns-panel"),
  dnsStatsStrip: document.querySelector("#dns-stats-strip"),
  dnsEngine: document.querySelector("#dns-engine"),
  dnsProtection: document.querySelector("#dns-protection"),
  protectionDbSummary: document.querySelector("#protection-db-summary"),
  blocklistTable: document.querySelector("#blocklist-table"),
  protectionLookupInput: document.querySelector("#protection-lookup-input"),
  protectionLookupButton: document.querySelector("#protection-lookup-button"),
  protectionLookupResult: document.querySelector("#protection-lookup-result"),
  piholePanel: document.querySelector("#pihole-panel"),
  piholeSettingsButton: document.querySelector("#pihole-settings-button"),
  piholeBack: document.querySelector("#pihole-back"),
  piholeAdminLink: document.querySelector("#pihole-admin-link"),
  piholeStatusStrip: document.querySelector("#pihole-status-strip"),
  piholeBlockingLabel: document.querySelector("#pihole-blocking-label"),
  piholeConsole: document.querySelector("#pihole-console"),
  piholeEnable: document.querySelector("#pihole-enable"),
  piholeDisable: document.querySelector("#pihole-disable"),
  piholeDisableTemp: document.querySelector("#pihole-disable-temp"),
  piholeDisableDuration: document.querySelector("#pihole-disable-duration"),
  piholeGravity: document.querySelector("#pihole-gravity"),
  piholeReload: document.querySelector("#pihole-reload"),
  piholeFlush: document.querySelector("#pihole-flush"),
  piholeDomainInput: document.querySelector("#pihole-domain-input"),
  piholeAllow: document.querySelector("#pihole-allow"),
  piholeDeny: document.querySelector("#pihole-deny"),
  piholeAllowRemove: document.querySelector("#pihole-allow-remove"),
  piholeDenyRemove: document.querySelector("#pihole-deny-remove"),
  themeButtons: Array.from(document.querySelectorAll("[data-theme-set]")),
  deviceGrid: document.querySelector("#device-grid"),
  profileList: document.querySelector("#profile-list"),
  requestDevice: document.querySelector("#request-device"),
  requestDomain: document.querySelector("#request-domain"),
  requestReason: document.querySelector("#request-reason"),
  requestCreate: document.querySelector("#request-create"),
  accessRequestList: document.querySelector("#access-request-list"),
  refresh: document.querySelector("#refresh-button"),
  refresh2: document.querySelector("#refresh-button-2"),
  identify: document.querySelector("#identify-button"),
  rollback: document.querySelector("#rollback-button"),
  deviceBack: document.querySelector("#device-back"),
  deviceTitle: document.querySelector("#device-page-title"),
  deviceEyebrow: document.querySelector("#device-page-eyebrow"),
  deviceState: document.querySelector("#device-page-state"),
  deviceLivePulse: document.querySelector("#device-live-pulse"),
  deviceLiveFeed: document.querySelector("#device-live-feed"),
  deviceSearchFeed: document.querySelector("#device-search-feed"),
  deviceServices: document.querySelector("#device-services"),
  deviceConnections: document.querySelector("#device-connections"),
  deviceTopRemotes: document.querySelector("#device-top-remotes"),
  deviceProtocolChips: document.querySelector("#device-protocol-chips"),
  deviceBandwidthChart: document.querySelector("#device-bandwidth-chart"),
  deviceInfo: document.querySelector("#device-info"),
  deviceStatsStrip: document.querySelector("#device-stats-strip"),
  deviceDnsBanner: document.querySelector("#device-dns-banner"),
  deviceTrafficChart: document.querySelector("#device-traffic-chart"),
  statsStrip: document.querySelector("#stats-strip"),
  trafficChart: document.querySelector("#traffic-chart"),
  activityFeed: document.querySelector("#activity-feed"),
  topServices: document.querySelector("#top-services"),
  topDevices: document.querySelector("#top-devices"),
  bandwidthList: document.querySelector("#bandwidth-list"),
  onpathFlows: document.querySelector("#onpath-flows"),
  activitySearch: document.querySelector("#activity-search"),
  activityDevice: document.querySelector("#activity-device"),
  activityCategory: document.querySelector("#activity-category"),
  activityStatus: document.querySelector("#activity-status"),
  activityWindowLabel: document.querySelector("#activity-window-label"),
  monitorPulse: document.querySelector("#monitor-pulse"),
  alertsPanel: document.querySelector("#alerts-panel"),
  alertsList: document.querySelector("#alerts-list"),
  alertBadge: document.querySelector("#alert-badge"),
  ackAllAlerts: document.querySelector("#ack-all-alerts"),
  alertReportPanel: document.querySelector("#alert-report-panel"),
  alertReportBack: document.querySelector("#alert-report-back"),
  alertReportTitle: document.querySelector("#alert-report-title"),
  alertReportEyebrow: document.querySelector("#alert-report-eyebrow"),
  alertReportSeverity: document.querySelector("#alert-report-severity"),
  alertReportBody: document.querySelector("#alert-report-body"),
  setupBanner: document.querySelector("#setup-banner"),
  deviceHistoryChart: document.querySelector("#device-history-chart"),
  historyWindowToggle: document.querySelector("#history-window-toggle"),
  reportsPanel: document.querySelector("#reports-panel"),
  reportPeriod: document.querySelector("#report-period"),
  reportPrivacy: document.querySelector("#report-privacy"),
  reportExport: document.querySelector("#report-export"),
  reportSummary: document.querySelector("#report-summary"),
  reportServices: document.querySelector("#report-services"),
  reportCategories: document.querySelector("#report-categories"),
  reportAlerts: document.querySelector("#report-alerts"),
  reportDomains: document.querySelector("#report-domains"),
  systemPanel: document.querySelector("#system-panel"),
  systemRefresh: document.querySelector("#system-refresh"),
  emergencyDnsOnly: document.querySelector("#emergency-dns-only"),
  systemSummary: document.querySelector("#system-summary"),
  systemServices: document.querySelector("#system-services"),
  systemResources: document.querySelector("#system-resources"),
  systemActions: document.querySelector("#system-actions"),
  settingsPanel: document.querySelector("#settings-panel"),
  capabilityList: document.querySelector("#capability-list"),
  communityPanel: document.querySelector("#community-panel"),
  networkSettingsPanel: document.querySelector("#network-settings-panel"),
  retentionPanel: document.querySelector("#retention-panel"),
  securityStatus: document.querySelector("#security-status"),
  auditList: document.querySelector("#audit-list"),
};

elements.refresh?.addEventListener("click", () => refreshDevices());
elements.refresh2?.addEventListener("click", () => refreshDevices());
elements.identify?.addEventListener("click", () => identifyDevices());
elements.rollback?.addEventListener("click", () => rollbackNetwork());
elements.deviceBack?.addEventListener("click", () => closeDevicePage());
elements.tabs.forEach((tab) => tab.addEventListener("click", () => activateTab(tab.dataset.tabTarget)));
elements.activitySearch?.addEventListener("input", () => {
  state.filters.q = elements.activitySearch.value.trim();
  reloadActivity(true);
});
elements.activityDevice?.addEventListener("change", () => {
  state.filters.client = elements.activityDevice.value;
  reloadActivity(true);
});
elements.activityCategory?.addEventListener("change", () => {
  state.filters.category = elements.activityCategory.value;
  reloadActivity(true);
});
elements.activityStatus?.addEventListener("change", () => {
  state.filters.status = elements.activityStatus.value;
  reloadActivity(true);
});
elements.ackAllAlerts?.addEventListener("click", () => ackAllAlerts());
elements.alertReportBack?.addEventListener("click", () => closeAlertReport());
elements.historyWindowToggle?.querySelectorAll("[data-history-window]").forEach((button) => {
  button.addEventListener("click", () => {
    state.historyWindow = button.dataset.historyWindow || "24h";
    elements.historyWindowToggle.querySelectorAll("[data-history-window]").forEach((node) => {
      node.classList.toggle("active-window", node === button);
    });
    loadHistory();
  });
});
elements.globalSearch?.addEventListener("input", () => {
  state.globalSearch = elements.globalSearch.value.trim().toLowerCase();
  renderDeviceGrid();
  renderServicesPanel();
  renderOverview();
});
elements.modeToggle?.addEventListener("click", () => setUiMode(state.uiMode === "simple" ? "advanced" : "simple"));
elements.piholeSettingsButton?.addEventListener("click", () => activateTab("pihole"));
elements.piholeBack?.addEventListener("click", () => activateTab("dns"));
elements.piholeEnable?.addEventListener("click", () => runPiholeAction("enable"));
elements.piholeDisable?.addEventListener("click", () => runPiholeAction("disable"));
elements.piholeDisableTemp?.addEventListener("click", () => runPiholeAction("disable-temp"));
elements.piholeGravity?.addEventListener("click", () => runPiholeAction("gravity"));
elements.piholeReload?.addEventListener("click", () => runPiholeAction("reload"));
elements.piholeFlush?.addEventListener("click", () => runPiholeAction("flush"));
elements.piholeAllow?.addEventListener("click", () => runPiholeDomain("allow", "add"));
elements.piholeDeny?.addEventListener("click", () => runPiholeDomain("deny", "add"));
elements.piholeAllowRemove?.addEventListener("click", () => runPiholeDomain("allow", "remove"));
elements.piholeDenyRemove?.addEventListener("click", () => runPiholeDomain("deny", "remove"));
elements.protectionLookupButton?.addEventListener("click", () => lookupProtectionDomain());
elements.protectionLookupInput?.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    lookupProtectionDomain();
  }
});
elements.requestCreate?.addEventListener("click", () => createAccessRequest());
elements.reportPeriod?.addEventListener("change", () => loadReport());
elements.reportPrivacy?.addEventListener("change", () => loadReport());
elements.reportExport?.addEventListener("click", () => exportReportCsv());
elements.systemRefresh?.addEventListener("click", () => loadSystemHealth());
elements.emergencyDnsOnly?.addEventListener("click", () => applyEmergencyDnsOnly());
elements.themeButtons.forEach((button) => {
  button.addEventListener("click", () => setTheme(button.dataset.themeSet || "lcars"));
});
window.addEventListener("hashchange", () => syncRouteFromHash());
initTheme();
initUiMode();

async function getJson(path) {
  const response = await fetch(path, { credentials: "same-origin" });
  if (!response.ok) {
    throw new Error(`${path} returned ${response.status}`);
  }
  return response.json();
}

async function postJson(path, body = {}) {
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.detail || `${path} returned ${response.status}`);
  }
  return payload;
}

async function patchJson(path, body = {}) {
  const response = await fetch(path, {
    method: "PATCH",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.detail || `${path} returned ${response.status}`);
  }
  return payload;
}

async function refresh() {
  try {
    const [health, config, profiles, pihole] = await Promise.all([
      getJson("/api/health"),
      getJson("/api/config-summary"),
      getJson("/api/profiles"),
      getJson("/api/pihole"),
    ]);
    state.health = health;
    state.config = config;
    state.profiles = profiles;
    state.pihole = pihole;
    await refreshInventory(false);
    await Promise.all([loadAlerts(), loadSetup()]);
    render();
    if (state.activeTab === "activity") {
      await loadHistory();
      await reloadActivity(false);
    }
    if (state.activeTab === "overview") {
      await loadOverview();
    }
    if (state.activeTab === "services") {
      await loadServices();
    }
    if (state.activeTab === "alerts") {
      renderAlerts();
    }
    if (state.activeTab === "dns" || state.activeTab === "pihole") {
      await loadProtectionDatabase();
      renderDnsPanel();
    }
    if (state.activeTab === "controls") {
      await loadAccessRequests();
    }
    if (state.activeTab === "reports") {
      await loadReport();
    }
    if (state.activeTab === "system") {
      await loadSystemHealth();
    }
    if (state.activeTab === "settings") {
      await loadSettingsPanels();
    }
    if (state.selectedIp) {
      await loadDevicePage(state.selectedIp, false);
    }
  } catch (error) {
    elements.healthPill.textContent = "Offline";
    elements.healthPill.className = "health-pill bad";
    if (elements.deviceGrid) {
      elements.deviceGrid.innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
    }
  }
}

async function refreshInventory(full) {
  if (state.scanning) {
    return state.devices;
  }
  state.scanning = true;
  elements.monitorPulse?.classList.add("scanning");
  try {
    const payload = await postJson("/api/devices/refresh", { full: Boolean(full) });
    state.devices = payload.devices || [];
    state.lastInventoryAt = Date.now();
    renderDeviceGrid();
    renderActivityDeviceFilter();
    renderAccessRequestDeviceSelect();
    updateDeviceMetrics();
    return state.devices;
  } finally {
    state.scanning = false;
    elements.monitorPulse?.classList.remove("scanning");
  }
}

async function refreshDevices() {
  await runAction("Network scan complete", async () => {
    await refreshInventory(true);
    await refresh();
  });
}

async function identifyDevices() {
  await runAction("Labels refreshed", async () => {
    await postJson("/api/devices/identify");
    await refreshInventory(true);
    await refresh();
  });
}

async function setDeviceTarget(device, enabled) {
  const label = displayName(device);
  if (
    enabled &&
    !window.confirm(`Link ${label} through Pi-Circle?\n\nEnables on-path bandwidth + connection inspection.`)
  ) {
    return;
  }
  await runAction(enabled ? `Linked ${label}` : `Unlinked ${label}`, async () => {
    await postJson(`/api/devices/${encodeURIComponent(device.ip_address)}/arp-assisted`, { enabled });
    await wait(700);
    await refresh();
  });
}

async function saveDeviceIdentity(device) {
  const nameInput = elements.deviceInfo.querySelector("#info-name");
  const typeSelect = elements.deviceInfo.querySelector("#info-type");
  await runAction(`Saved ${device.ip_address}`, async () => {
    await postJson(`/api/devices/${encodeURIComponent(device.ip_address)}/identity`, {
      display_name: nameInput.value.trim() || null,
      device_type: typeSelect.value,
    });
    await refresh();
  });
}

async function saveDeviceProfile(device, profileId) {
  await runAction(`Profile updated`, async () => {
    await postJson(`/api/devices/${encodeURIComponent(device.ip_address)}/profile`, {
      profile_id: profileId ? Number(profileId) : null,
    });
    await refresh();
  });
}

async function setDevicePaused(device, enabled) {
  const label = displayName(device);
  // Optimistic UI: flip paused state immediately.
  device.paused = enabled;
  if (device.policy) {
    device.policy.paused = enabled;
    device.policy.blocked = enabled && (device.policy.linked || isEnrolled(device) || isTargeted(device));
    device.policy.blockReason = enabled ? "paused" : null;
  }
  if (state.devicePage?.device?.ip_address === device.ip_address) {
    state.devicePage.device.paused = enabled;
    state.devicePage.policy = device.policy || state.devicePage.policy;
    renderDevicePage();
  }
  renderDeviceGrid();
  await runAction(enabled ? `Paused ${label}` : `Resumed ${label}`, async () => {
    const result = await postJson(`/api/devices/${encodeURIComponent(device.ip_address)}/pause`, { enabled });
    showStatus(result.message || (enabled ? "Paused" : "Resumed"), enabled && result.policy?.requiresLink ? "neutral" : "good");
    await wait(400);
    await refresh();
  });
}

async function loadAlerts() {
  try {
    const payload = await getJson("/api/alerts?limit=40");
    state.alerts = payload.alerts || [];
    state.unackedAlerts = Number(payload.unackedCount || 0);
    renderAlertBadge();
    if (state.activeTab === "alerts") {
      renderAlerts();
    }
  } catch (_error) {
    // Keep previous alerts if the inbox endpoint is briefly unavailable.
  }
}

async function loadSetup() {
  try {
    state.setup = await getJson("/api/setup");
    renderSetupBanner();
  } catch (_error) {
    // Setup banner is advisory only.
  }
}

async function loadHistory() {
  try {
    state.history = await getJson(`/api/history?window=${encodeURIComponent(state.historyWindow)}`);
    renderHistory();
  } catch (error) {
    if (elements.statsStrip) {
      elements.statsStrip.innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
    }
  }
}

async function loadOverview() {
  try {
    const [overview, history] = await Promise.all([
      getJson("/api/analytics/overview?window=86400"),
      getJson("/api/history?window=24h"),
    ]);
    state.overview = { overview, history };
    renderOverview();
  } catch (error) {
    if (elements.overviewStatus) {
      elements.overviewStatus.innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
    }
  }
}

async function loadServices() {
  try {
    state.overview = state.overview || {};
    state.overview.overview = await getJson("/api/analytics/overview?window=86400");
    renderServicesPanel();
  } catch (error) {
    if (elements.serviceGrid) {
      elements.serviceGrid.innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
    }
  }
}

async function ackAllAlerts() {
  await runAction("Inbox cleared — alerts marked as read", async () => {
    await postJson("/api/alerts/ack-all");
    await loadAlerts();
    if (state.activeTab === "alert-report") {
      closeAlertReport();
    }
  });
}

async function ackAlert(alertId) {
  await runAction("Marked as read", async () => {
    await postJson(`/api/alerts/${alertId}/ack`);
    await loadAlerts();
    if (state.selectedAlertId === alertId) {
      closeAlertReport();
    }
  });
}

async function saveProfileSchedule(profileId) {
  const start = document.querySelector(`#profile-${profileId}-start`)?.value?.trim() || "";
  const end = document.querySelector(`#profile-${profileId}-end`)?.value?.trim() || "";
  const dailyRaw = document.querySelector(`#profile-${profileId}-daily`)?.value;
  const clearBedtime = !start && !end;
  const body = {
    clear_bedtime: clearBedtime,
    clear_daily_minutes: dailyRaw === "",
  };
  if (!clearBedtime) {
    body.bedtime_start = start;
    body.bedtime_end = end;
  }
  if (dailyRaw !== "") {
    body.daily_minutes = Number(dailyRaw);
  }
  await runAction("Profile schedule saved", async () => {
    const response = await fetch(`/api/profiles/${profileId}`, {
      method: "PATCH",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.detail || `profile update failed (${response.status})`);
    }
    await refresh();
  });
}

async function rollbackNetwork() {
  await runAction("Rollback complete", async () => {
    await postJson("/api/network/rollback");
    await wait(700);
    await refresh();
  });
}

async function runAction(successMessage, action) {
  if (state.busy) {
    return;
  }
  state.busy = true;
  showStatus("Working...", "neutral");
  try {
    await action();
    showStatus(successMessage, "good");
  } catch (error) {
    showStatus(error.message, "bad");
  } finally {
    state.busy = false;
  }
}

function render() {
  const healthy = Boolean(state.health?.network?.healthy);
  elements.healthPill.textContent = healthy ? "Nominal" : "Alert";
  elements.healthPill.className = `health-pill ${healthy ? "good" : "bad"}`;
  elements.mode.textContent = state.health?.mode ?? "Unknown";
  elements.interfaceName.textContent = state.health?.interface ?? "Unknown";
  updateDeviceMetrics();
  elements.adlistCount.textContent = formatNumber(state.pihole?.enabled_adlists ?? 0);
  elements.gravityCount.textContent = formatCompact(state.pihole?.gravity_domains ?? 0);
  if (elements.stardate) {
    elements.stardate.textContent = `STARDATE ${formatStardate(new Date())}`;
  }
  renderDeviceGrid();
  renderProfiles();
  renderActivityDeviceFilter();
  renderAccessRequestDeviceSelect();
  renderAccessRequests();
  renderDeviceInfo();
  renderAlertBadge();
  renderSetupBanner();
  renderOverview();
  renderServicesPanel();
  if (state.activeTab === "dns") {
    renderDnsPanel();
  }
}

function updateDeviceMetrics() {
  const online = state.devices.filter((device) => device.online !== false).length;
  elements.deviceCount.textContent = String(online);
  elements.targetCount.textContent = String(state.config?.transparentControl?.targetCount ?? 0);
}

function renderDeviceGrid() {
  if (!elements.deviceGrid) {
    return;
  }
  if (!state.devices.length) {
    elements.deviceGrid.innerHTML = '<div class="empty">Scanning for devices…</div>';
    return;
  }
  elements.deviceGrid.innerHTML = "";
  const devices = filterDevices(state.devices);
  if (!devices.length) {
    elements.deviceGrid.innerHTML = '<div class="empty">No devices match that search.</div>';
    return;
  }
  devices.forEach((device) => {
    const online = device.online !== false;
    const card = document.createElement("button");
    card.type = "button";
    card.className = "device-card";
    if (!online) {
      card.classList.add("offline");
    }
    if (isTargeted(device) || isEnrolled(device)) {
      card.classList.add("linked");
    }
    card.addEventListener("click", () => openDevicePage(device.ip_address));
    const type = effectiveDeviceType(device);
    const policy = device.policy || {};
    const status = isGateway(device)
      ? "Router"
      : policy.blocked
        ? policy.blockReason === "bedtime"
          ? "Bedtime"
          : policy.blockReason === "daily_limit"
            ? "Limit"
            : "Paused"
        : !online
          ? "Offline"
          : isTargeted(device) || isEnrolled(device)
            ? "Linked"
            : "Online";
    if (policy.blocked || device.paused) {
      card.classList.add("paused");
    }
    card.innerHTML = `
      <div class="device-card-icon type-${type}">${deviceIcon(type)}</div>
      <div class="device-card-copy">
        <p class="device-card-name">${escapeHtml(displayName(device))}</p>
        <p class="device-card-meta">${escapeHtml([device.vendor, typeLabel(type), device.ip_address].filter(Boolean).join(" · "))}</p>
        <p class="device-card-meta">${escapeHtml(device.hostname || device.mac_address || "Discovered on LAN")}</p>
        <p class="device-card-meta">${escapeHtml(deviceCapabilityLabel(device))}</p>
      </div>
      <span class="state ${policy.blocked || device.paused ? "paused" : online ? (isTargeted(device) || isEnrolled(device) ? "linked" : "online") : "offline"}">
        <span class="presence-dot"></span>${escapeHtml(status)}
      </span>
    `;
    elements.deviceGrid.appendChild(card);
  });
}

function filterDevices(devices) {
  const q = state.globalSearch;
  if (!q) {
    return devices;
  }
  return devices.filter((device) =>
    [
      displayName(device),
      device.hostname,
      device.vendor,
      device.ip_address,
      device.mac_address,
      typeLabel(effectiveDeviceType(device)),
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase()
      .includes(q)
  );
}

function renderProfiles() {
  if (!elements.profileList) {
    return;
  }
  if (!state.profiles.length) {
    elements.profileList.innerHTML = '<div class="empty">No profiles available.</div>';
    return;
  }
  elements.profileList.innerHTML = "";
  state.profiles.forEach((profile) => {
    const card = document.createElement("article");
    card.className = "profile-card";
    const bedtime =
      profile.bedtime_start && profile.bedtime_end
        ? `${profile.bedtime_start} → ${profile.bedtime_end}`
        : "No bedtime";
    const budget = profile.daily_minutes ? `${profile.daily_minutes} min/day` : "No daily limit";
    card.innerHTML = `
      <div class="profile-card-head">
        <strong>${escapeHtml(profile.name)}</strong>
        <span>${profile.device_count} device(s)</span>
      </div>
      <p class="device-card-meta">${escapeHtml(profile.description || "No description")}</p>
      <p class="device-card-meta">${escapeHtml(bedtime)} · ${escapeHtml(budget)}</p>
      <details class="advanced-details">
        <summary>Protection settings</summary>
        <ul class="profile-control-list">
          ${profileProtectionItems(profile).map((item) => `<li>${escapeHtml(item)}</li>`).join("")}
        </ul>
      </details>
      <div class="profile-edit-grid">
        <label class="field-label">Bedtime start
          <input class="name-input" id="profile-${profile.id}-start" type="time" value="${escapeAttribute(toTimeInput(profile.bedtime_start))}" />
        </label>
        <label class="field-label">Bedtime end
          <input class="name-input" id="profile-${profile.id}-end" type="time" value="${escapeAttribute(toTimeInput(profile.bedtime_end))}" />
        </label>
        <label class="field-label">Daily minutes
          <input class="name-input" id="profile-${profile.id}-daily" type="number" min="0" max="1440" placeholder="None" value="${profile.daily_minutes ?? ""}" />
        </label>
      </div>
      <button class="secondary-button compact" type="button" data-save-profile="${profile.id}">Save schedule</button>
    `;
    card.querySelector("[data-save-profile]")?.addEventListener("click", () => saveProfileSchedule(profile.id));
    elements.profileList.appendChild(card);
  });
}

function profileProtectionItems(profile) {
  const name = String(profile.name || "").toLowerCase();
  if (name.includes("parent") || name.includes("adult")) {
    return [
      "Unrestricted adult profile by default.",
      "Pi-hole DNS filtering still applies globally unless Pi-hole blocking is disabled.",
      "No HTTPS content inspection is performed.",
    ];
  }
  if (name.includes("kid") || name.includes("child")) {
    return [
      "Bedtime and daily allowance can pause linked-device internet access.",
      "Unlinked devices receive DNS-level Pi-hole filtering only.",
      "Service identification is based on domains and shown as an estimate.",
    ];
  }
  if (name.includes("guest")) {
    return [
      "Useful for temporary household devices.",
      "DNS blocking is provided by Pi-hole.",
      "Gateway-level pause requires the device to be linked.",
    ];
  }
  return [
    "Custom schedule and daily allowance can be edited here.",
    "Domain allow/deny rules are managed through Pi-hole controls.",
    "Capability labels separate DNS blocking from internet pause.",
  ];
}

function renderAccessRequestDeviceSelect() {
  if (!elements.requestDevice) {
    return;
  }
  const current = elements.requestDevice.value;
  elements.requestDevice.innerHTML = "";
  if (!state.devices.length) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "No devices found";
    elements.requestDevice.appendChild(option);
    return;
  }
  state.devices.forEach((device) => {
    const option = document.createElement("option");
    option.value = device.ip_address;
    option.textContent = `${displayName(device)} · ${device.ip_address}`;
    option.selected = current === device.ip_address;
    elements.requestDevice.appendChild(option);
  });
}

async function loadAccessRequests() {
  if (!elements.accessRequestList) {
    return;
  }
  try {
    const payload = await getJson("/api/access-requests?include_decided=true&limit=50");
    state.accessRequests = payload.requests || [];
    state.accessRequestDeviceNames = payload.deviceNames || {};
    renderAccessRequests();
  } catch (error) {
    elements.accessRequestList.innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
  }
}

function renderAccessRequests() {
  if (!elements.accessRequestList) {
    return;
  }
  if (!state.accessRequests.length) {
    elements.accessRequestList.innerHTML = '<div class="empty">No access requests yet.</div>';
    return;
  }
  elements.accessRequestList.innerHTML = "";
  state.accessRequests.forEach((item) => {
    const row = document.createElement("article");
    row.className = `request-card request-${escapeAttribute(item.status || "pending")}`;
    const deviceName = state.accessRequestDeviceNames[item.device_ip] || item.device_ip;
    const status = String(item.status || "pending");
    row.innerHTML = `
      <div>
        <div class="request-title">
          <strong>${escapeHtml(item.domain)}</strong>
          <span class="state ${status === "pending" ? "warn" : status === "approved" ? "good" : "bad"}">${escapeHtml(status)}</span>
        </div>
        <p class="device-card-meta">${escapeHtml(deviceName)} · ${escapeHtml(item.service || "Domain request")} · ${escapeHtml(formatIsoTime(item.created_at))}</p>
        <p class="device-card-meta">${escapeHtml(item.reason || "No reason provided")}</p>
        ${item.decision ? `<p class="device-card-meta">Decision: ${escapeHtml(decisionLabel(item.decision))}</p>` : ""}
      </div>
      ${
        status === "pending"
          ? `<div class="request-actions">
              <button class="primary-button compact" type="button" data-request-decision="always_allow">Always allow</button>
              <button class="danger-button compact" type="button" data-request-decision="deny">Deny</button>
            </div>`
          : ""
      }
    `;
    row.querySelectorAll("[data-request-decision]").forEach((button) => {
      button.addEventListener("click", () => decideAccessRequest(item.id, button.dataset.requestDecision));
    });
    elements.accessRequestList.appendChild(row);
  });
}

async function createAccessRequest() {
  const deviceIp = elements.requestDevice?.value || "";
  const domain = elements.requestDomain?.value.trim() || "";
  const reason = elements.requestReason?.value.trim() || "";
  if (!deviceIp || !domain) {
    showStatus("Choose a device and enter a domain", "bad");
    return;
  }
  try {
    await postJson("/api/access-requests", { device_ip: deviceIp, domain, reason });
    if (elements.requestDomain) elements.requestDomain.value = "";
    if (elements.requestReason) elements.requestReason.value = "";
    await loadAccessRequests();
    showStatus("Access request added", "good");
  } catch (error) {
    showStatus(error.message, "bad");
  }
}

async function decideAccessRequest(requestId, decision) {
  try {
    const payload = await postJson(`/api/access-requests/${encodeURIComponent(requestId)}/decision`, { decision });
    if (payload.result) {
      appendPiholeConsole(payload.result.stdout || `Access request ${decisionLabel(decision)} applied`);
    }
    await loadAccessRequests();
    await refresh();
    showStatus(`Request ${decisionLabel(decision).toLowerCase()}`, "good");
  } catch (error) {
    showStatus(error.message, "bad");
  }
}

function decisionLabel(decision) {
  const labels = {
    always_allow: "Always allowed",
    allow_once: "Allowed once",
    allow_15m: "Allowed for 15 minutes",
    allow_1h: "Allowed for one hour",
    deny: "Denied",
  };
  return labels[decision] || decision || "Unknown";
}

function renderActivityDeviceFilter() {
  if (!elements.activityDevice) {
    return;
  }
  const current = state.filters.client;
  elements.activityDevice.innerHTML = '<option value="">All devices</option>';
  state.devices.forEach((device) => {
    const option = document.createElement("option");
    option.value = device.ip_address;
    option.textContent = displayName(device);
    option.selected = current === device.ip_address;
    elements.activityDevice.appendChild(option);
  });
}

function hideAllPanels() {
  [
    elements.overviewPanel,
    elements.homePanel,
    elements.activityPanel,
    elements.servicesPanel,
    elements.dnsPanel,
    elements.piholePanel,
    elements.alertsPanel,
    elements.alertReportPanel,
    elements.controlsPanel,
    elements.reportsPanel,
    elements.systemPanel,
    elements.settingsPanel,
    elements.devicePage,
  ].forEach((panel) => {
    panel?.classList.add("hidden");
    panel?.setAttribute("aria-hidden", "true");
  });
}

function scrollAppTop() {
  document.querySelector(".app-scroll")?.scrollTo({ top: 0, behavior: "smooth" });
}

function activateTab(target) {
  state.activeTab = target;
  state.selectedAlertId = null;
  elements.tabs.forEach((tab) => {
    const active = tab.dataset.tabTarget === target || (target === "pihole" && tab.dataset.tabTarget === "dns");
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-current", active ? "page" : "false");
  });
  stopActivityPolling();
  hideAllPanels();
  if (target === "home") {
    stopDevicePolling();
    state.selectedIp = null;
    state.devicePage = null;
    elements.homePanel?.classList.remove("hidden");
    elements.homePanel?.setAttribute("aria-hidden", "false");
    history.replaceState(null, "", "#home");
  }
  if (target === "overview") {
    stopDevicePolling();
    state.selectedIp = null;
    elements.overviewPanel?.classList.remove("hidden");
    elements.overviewPanel?.setAttribute("aria-hidden", "false");
    history.replaceState(null, "", "#overview");
    loadOverview();
  }
  if (target === "activity") {
    stopDevicePolling();
    state.selectedIp = null;
    elements.activityPanel?.classList.remove("hidden");
    elements.activityPanel?.setAttribute("aria-hidden", "false");
    history.replaceState(null, "", "#activity");
    loadHistory();
    reloadActivity(true);
    startActivityPolling();
  }
  if (target === "services") {
    stopDevicePolling();
    state.selectedIp = null;
    elements.servicesPanel?.classList.remove("hidden");
    elements.servicesPanel?.setAttribute("aria-hidden", "false");
    history.replaceState(null, "", "#services");
    loadServices();
  }
  if (target === "dns") {
    stopDevicePolling();
    state.selectedIp = null;
    elements.dnsPanel?.classList.remove("hidden");
    elements.dnsPanel?.setAttribute("aria-hidden", "false");
    history.replaceState(null, "", "#dns");
    renderDnsPanel();
    loadProtectionDatabase();
  }
  if (target === "pihole") {
    stopDevicePolling();
    state.selectedIp = null;
    elements.piholePanel?.classList.remove("hidden");
    elements.piholePanel?.setAttribute("aria-hidden", "false");
    history.replaceState(null, "", "#pihole");
    renderDnsPanel();
    loadProtectionDatabase();
    loadPiholeStatus();
  }
  if (target === "alerts") {
    stopDevicePolling();
    state.selectedIp = null;
    elements.alertsPanel?.classList.remove("hidden");
    elements.alertsPanel?.setAttribute("aria-hidden", "false");
    history.replaceState(null, "", "#alerts");
    loadAlerts();
  }
  if (target === "controls") {
    stopDevicePolling();
    state.selectedIp = null;
    elements.controlsPanel?.classList.remove("hidden");
    elements.controlsPanel?.setAttribute("aria-hidden", "false");
    history.replaceState(null, "", "#controls");
    loadAccessRequests();
  }
  if (target === "reports") {
    stopDevicePolling();
    state.selectedIp = null;
    elements.reportsPanel?.classList.remove("hidden");
    elements.reportsPanel?.setAttribute("aria-hidden", "false");
    history.replaceState(null, "", "#reports");
    loadReport();
  }
  if (target === "system") {
    stopDevicePolling();
    state.selectedIp = null;
    elements.systemPanel?.classList.remove("hidden");
    elements.systemPanel?.setAttribute("aria-hidden", "false");
    history.replaceState(null, "", "#system");
    loadSystemHealth();
  }
  if (target === "settings") {
    stopDevicePolling();
    state.selectedIp = null;
    elements.settingsPanel?.classList.remove("hidden");
    elements.settingsPanel?.setAttribute("aria-hidden", "false");
    history.replaceState(null, "", "#settings");
    loadSettingsPanels();
  }
  scrollAppTop();
}

function openDevicePage(ipAddress) {
  const ip = String(ipAddress || "").trim();
  if (!ip) {
    showStatus("No device is linked to this alert", "bad");
    return;
  }
  state.selectedIp = ip;
  state.selectedAlertId = null;
  state.activeTab = "device";
  stopActivityPolling();
  elements.tabs.forEach((tab) => {
    const active = tab.dataset.tabTarget === "home";
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-current", active ? "page" : "false");
  });
  hideAllPanels();
  elements.devicePage?.classList.remove("hidden");
  elements.devicePage?.setAttribute("aria-hidden", "false");
  history.replaceState(null, "", `#device/${encodeURIComponent(ip)}`);
  scrollAppTop();
  loadDevicePage(ip, true);
  startDevicePolling();
}

function closeDevicePage(updateHash = true) {
  stopDevicePolling();
  state.selectedIp = null;
  state.devicePage = null;
  elements.devicePage?.classList.add("hidden");
  elements.devicePage?.setAttribute("aria-hidden", "true");
  elements.homePanel?.classList.remove("hidden");
  elements.homePanel?.setAttribute("aria-hidden", "false");
  if (updateHash) {
    history.replaceState(null, "", "#home");
  }
}

function renderHistory() {
  const data = state.history;
  if (!data) {
    return;
  }
  const totals = data.totals || {};
  const blockedPct = totals.queries ? ((totals.blocked / totals.queries) * 100).toFixed(1) : "0.0";
  if (elements.activityWindowLabel) {
    const labels = { "1h": "Last hour", "24h": "Last 24 hours", "7d": "Last 7 days" };
    elements.activityWindowLabel.textContent = labels[data.window] || data.window;
  }
  if (elements.statsStrip) {
    elements.statsStrip.innerHTML = [
      metricCard("Queries", formatCompact(totals.queries || 0)),
      metricCard("Blocked", `${blockedPct}%`),
      metricCard("Peak devices", formatNumber(totals.devices || 0)),
      metricCard("Window", data.window || state.historyWindow),
    ].join("");
  }
  renderTrafficChart(elements.trafficChart, data.series || []);
  renderRankList(elements.topServices, data.topServices || [], (row) => row.name, (row) => row.count);
  // Keep live side lists fresh from analytics-lite fallback when available.
  getJson("/api/analytics/overview?window=3600")
    .then((overview) => {
      state.analytics = overview;
      renderRankList(
        elements.topDevices,
        overview.overview?.topClients || [],
        (row) => row.name || row.ip,
        (row) => row.count,
        (row) => openDevicePage(row.ip)
      );
      renderBandwidthList(overview.bandwidth || []);
      loadOnpathFlows();
    })
    .catch(() => {
      loadOnpathFlows();
    });
}

function renderOverview() {
  if (!elements.overviewPanel) {
    return;
  }
  const healthOk = Boolean(state.health?.network?.healthy);
  const piholeOk = state.pihole?.installed && state.pihole?.ftl_listening !== false;
  const setupOk = Boolean(state.setup?.ready);
  const totals = state.overview?.overview?.overview?.totals || {};
  const history = state.overview?.history || {};
  const online = state.devices.filter((device) => device.online !== false).length;
  const linked = Number(state.config?.transparentControl?.targetCount || 0);
  const unknown = state.devices.filter((device) => effectiveDeviceType(device) === "unknown").length;
  const blockedPct = totals.queries ? `${totals.blockedPercent || 0}%` : "0%";
  if (elements.overviewSummary) {
    elements.overviewSummary.textContent = setupOk
      ? "DNS filtering, device discovery, profiles, alerts, and Pi-hole list updates are reporting."
      : "Some setup checks need attention. Pi-Circle will show only capabilities that are actually available.";
  }
  if (elements.overviewStatus) {
    elements.overviewStatus.innerHTML = [
      statusRow("Pi-Circle appliance", healthOk ? "Healthy" : "Needs attention", healthOk ? "good" : "bad"),
      statusRow("Pi-hole DNS filtering", piholeOk ? "Active" : "Unavailable", piholeOk ? "good" : "bad"),
      statusRow("Device discovery", online ? `${online} online` : "Waiting", online ? "good" : "warn"),
      statusRow("Linked enforcement", linked ? `${linked} linked` : "DNS-only protection", linked ? "good" : "warn"),
      statusRow("List updates", formatGravityUpdateSummary(state.pihole?.gravity_update), "good"),
    ].join("");
  }
  if (elements.overviewMetrics) {
    elements.overviewMetrics.innerHTML = [
      metricCard("Online", online),
      metricCard("Protected", linked || "DNS"),
      metricCard("Unknown", unknown),
      metricCard("DNS today", formatCompact(totals.queries || 0)),
      metricCard("Blocked today", formatCompact(totals.blocked || 0)),
      metricCard("Blocked %", blockedPct),
      metricCard("Alerts", state.unackedAlerts || 0),
      metricCard("Database", formatCompact(state.pihole?.gravity_domains || 0)),
    ].join("");
  }
  renderTrafficChart(elements.overviewChart, history.series || state.overview?.overview?.series || []);
  renderRankList(
    elements.overviewDevices,
    filterOverviewRows(state.overview?.overview?.overview?.topClients || [], (row) => `${row.name || row.ip} ${row.ip}`),
    (row) => row.name || row.ip,
    (row) => `${formatCompact(row.count)} lookups`,
    (row) => openDevicePage(row.ip)
  );
  renderServiceRadar(elements.overviewServices, state.overview?.overview?.overview?.topServices || []);
  renderMiniAlerts();
}

function statusRow(label, value, tone) {
  return `<div class="status-row ${tone}"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`;
}

function renderMiniAlerts() {
  if (!elements.overviewAlerts) {
    return;
  }
  const alerts = state.alerts.slice(0, 4);
  if (!alerts.length) {
    elements.overviewAlerts.innerHTML = '<div class="empty">No unread alerts.</div>';
    return;
  }
  elements.overviewAlerts.innerHTML = "";
  alerts.forEach((alert) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `mini-alert ${alert.severity || "info"}`;
    button.innerHTML = `<strong>${escapeHtml(alert.title)}</strong><span>${escapeHtml(formatAlertWhen(alert.created_at))}</span>`;
    button.addEventListener("click", () => openAlertReport(alert.id));
    elements.overviewAlerts.appendChild(button);
  });
}

function renderServiceRadar(container, services) {
  if (!container) {
    return;
  }
  const rows = filterOverviewRows(services, (row) => row.name).slice(0, 8);
  if (!rows.length) {
    container.innerHTML = '<div class="empty">No DNS service matches yet.</div>';
    return;
  }
  container.innerHTML = "";
  rows.forEach((service) => {
    const item = document.createElement("div");
    item.className = "service-radar-item";
    const confidence = serviceConfidence(service.name);
    item.innerHTML = `
      <span class="service-icon">${escapeHtml(serviceInitials(service.name))}</span>
      <span>${escapeHtml(service.name)}</span>
      <strong>${escapeHtml(formatCompact(service.count))}</strong>
      <em>${escapeHtml(confidence)}</em>
    `;
    container.appendChild(item);
  });
}

function renderServicesPanel() {
  if (!elements.serviceGrid) {
    return;
  }
  const overview = state.overview?.overview?.overview;
  const services = overview?.topServices || [];
  const domains = overview?.topDomains || [];
  const categories = overview?.categories || [];
  const filtered = filterOverviewRows(services, (row) => row.name);
  if (elements.servicesSummary) {
    elements.servicesSummary.innerHTML = [
      metricCard("Services", services.length),
      metricCard("Categories", categories.length),
      metricCard("Domains", formatCompact(overview?.totals?.domains || 0)),
      metricCard("Method", "DNS estimate"),
    ].join("");
  }
  if (!filtered.length) {
    elements.serviceGrid.innerHTML = '<div class="empty">No matching services yet. Open apps or websites on protected devices and refresh.</div>';
    return;
  }
  elements.serviceGrid.innerHTML = "";
  filtered.forEach((service) => {
    const card = document.createElement("article");
    card.className = "service-insight-card";
    const confidence = serviceConfidence(service.name);
    const domainMatches = domains.filter((row) => serviceDomainMatch(service.name, row.domain)).slice(0, 4);
    card.innerHTML = `
      <div class="service-insight-head">
        <span class="service-icon">${escapeHtml(serviceInitials(service.name))}</span>
        <div>
          <h2>${escapeHtml(service.name)}</h2>
          <p>${escapeHtml(serviceCategoryLabel(service.name))} · ${escapeHtml(confidence)}</p>
        </div>
        <strong>${escapeHtml(formatCompact(service.count))}</strong>
      </div>
      <div class="service-domain-list">
        ${
          domainMatches.length
            ? domainMatches
                .map((row) => `<span>${escapeHtml(row.domain)} <strong>${escapeHtml(formatCompact(row.count))}</strong></span>`)
                .join("")
            : "<span>Supporting domains are in the DNS activity view.</span>"
        }
      </div>
      <p class="device-card-meta">Identification is based on DNS names only. It does not reveal HTTPS page content or in-app actions.</p>
    `;
    elements.serviceGrid.appendChild(card);
  });
}

function filterOverviewRows(rows, textFn) {
  const q = state.globalSearch;
  if (!q) {
    return rows;
  }
  return rows.filter((row) => String(textFn(row) || "").toLowerCase().includes(q));
}

function alertGuide(alertType) {
  return (
    ALERT_GUIDE[alertType] || {
      label: "Alert",
      meaning: "Something noteworthy happened on the household network.",
      action: "Open the report for details.",
    }
  );
}

function alertDeviceLabel(ip) {
  if (!ip) {
    return "Unknown device";
  }
  const device = state.devices.find((item) => item.ip_address === ip);
  return device ? `${displayName(device)} (${ip})` : ip;
}

function formatAlertWhen(value) {
  if (!value) {
    return "Just now";
  }
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) {
    return String(value);
  }
  const seconds = Math.max(0, Math.floor((Date.now() - parsed) / 1000));
  return `${formatAge(seconds)} ago`;
}

function renderAlerts() {
  if (!elements.alertsList) {
    return;
  }
  if (!state.alerts.length) {
    elements.alertsList.innerHTML =
      '<div class="empty">No unread alerts. You’re clear — new device, spike, or privacy notices will show up here.</div>';
    return;
  }
  elements.alertsList.innerHTML = "";
  state.alerts.forEach((alert) => {
    const guide = alertGuide(alert.alert_type);
    const row = document.createElement("article");
    row.className = `alert-card ${alert.severity || "info"} ${alert.acked ? "acked" : ""}`;
    row.innerHTML = `
      <div class="alert-copy">
        <p class="alert-kind">${escapeHtml(guide.label)}</p>
        <p class="alert-title">${escapeHtml(alert.title)}</p>
        <p class="alert-detail">${escapeHtml(alert.detail || guide.meaning)}</p>
        <p class="alert-meta">${escapeHtml(formatAlertWhen(alert.created_at))} · ${escapeHtml(
          alertDeviceLabel(alert.subject)
        )}</p>
      </div>
      <div class="action-row alert-actions">
        <button class="primary-button compact" type="button" data-report="${alert.id}">Open report</button>
        ${
          alert.acked
            ? '<span class="alert-read-tag">Read</span>'
            : `<button class="secondary-button compact" type="button" data-ack="${alert.id}" title="Clear from inbox only — does not change network rules">Mark as read</button>`
        }
      </div>
    `;
    row.querySelector("[data-ack]")?.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      ackAlert(alert.id);
    });
    row.querySelector("[data-report]")?.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      openAlertReport(alert.id);
    });
    elements.alertsList.appendChild(row);
  });
}

function openAlertReport(alertId) {
  const alert = state.alerts.find((item) => Number(item.id) === Number(alertId));
  if (!alert) {
    showStatus("That alert is no longer in the inbox", "bad");
    loadAlerts();
    return;
  }
  state.selectedAlertId = Number(alert.id);
  state.activeTab = "alert-report";
  stopActivityPolling();
  stopDevicePolling();
  elements.tabs.forEach((tab) => tab.classList.toggle("active", tab.dataset.tabTarget === "alerts"));
  hideAllPanels();
  elements.alertReportPanel?.classList.remove("hidden");
  history.replaceState(null, "", `#alert/${encodeURIComponent(String(alert.id))}`);
  renderAlertReport(alert);
  scrollAppTop();
}

function closeAlertReport() {
  state.selectedAlertId = null;
  activateTab("alerts");
}

function alertEvidenceParams(alert) {
  const type = String(alert.alert_type || "");
  // Blocked-burst shows blocked domains; other alerts show the busiest domains in that window.
  const focus = type === "blocked_burst" ? "blocked" : "all";
  const windowSeconds =
    type === "new_device" ? 3600 : type === "late_night" || type === "spike" || type === "blocked_burst" ? 300 : 900;
  let until = Math.floor(Date.now() / 1000);
  const parsed = Date.parse(alert.created_at || "");
  if (!Number.isNaN(parsed)) {
    // Look at the window ending when the alert fired (plus a small buffer).
    until = Math.floor(parsed / 1000) + 30;
  }
  return { focus, windowSeconds, until };
}

function renderAlertReport(alert) {
  const guide = alertGuide(alert.alert_type);
  const severity = String(alert.severity || "info");
  const deviceIp = alert.subject ? String(alert.subject) : "";
  if (elements.alertReportTitle) {
    elements.alertReportTitle.textContent = alert.title || guide.label;
  }
  if (elements.alertReportEyebrow) {
    elements.alertReportEyebrow.textContent = guide.label;
  }
  if (elements.alertReportSeverity) {
    elements.alertReportSeverity.textContent = severity === "warn" ? "Needs attention" : "FYI";
    elements.alertReportSeverity.className = `state ${severity === "warn" ? "paused" : "linked"}`;
  }
  if (!elements.alertReportBody) {
    return;
  }
  elements.alertReportBody.innerHTML = `
    <div class="alert-report-grid">
      <section class="alert-report-card alert-report-card-wide" id="alert-what-happened">
        <h2>What happened</h2>
        <p>${escapeHtml(alert.detail || guide.meaning)}</p>
        <p class="device-card-meta">${escapeHtml(guide.meaning)}</p>
        <div class="alert-evidence" id="alert-evidence">
          <div class="empty">Loading domains from this alert…</div>
        </div>
      </section>
      <section class="alert-report-card">
        <h2>When</h2>
        <p>${escapeHtml(formatAlertWhen(alert.created_at))}</p>
        <p class="device-card-meta">${escapeHtml(alert.created_at || "")}</p>
      </section>
      <section class="alert-report-card">
        <h2>Device</h2>
        <p>${escapeHtml(alertDeviceLabel(deviceIp))}</p>
        <p class="device-card-meta">${deviceIp ? "Open the device page for live DNS, history, and controls." : "No device IP was attached to this alert."}</p>
      </section>
      <section class="alert-report-card">
        <h2>What you can do</h2>
        <p>${escapeHtml(guide.action)}</p>
        <p class="device-card-meta"><strong>Mark as read</strong> only clears this notice from the inbox. <strong>Block domain</strong> adds it to Pi-hole’s denylist.</p>
      </section>
    </div>
    <div class="action-row alert-report-actions">
      ${
        deviceIp
          ? `<button class="primary-button" type="button" id="alert-view-device">View device activity</button>`
          : ""
      }
      ${
        alert.acked
          ? ""
          : `<button class="secondary-button" type="button" id="alert-mark-read">Mark as read</button>`
      }
      <button class="secondary-button" type="button" id="alert-back-inbox">Back to inbox</button>
    </div>
  `;
  elements.alertReportBody.querySelector("#alert-view-device")?.addEventListener("click", () => {
    openDevicePage(deviceIp);
  });
  elements.alertReportBody.querySelector("#alert-mark-read")?.addEventListener("click", () => {
    ackAlert(alert.id);
  });
  elements.alertReportBody.querySelector("#alert-back-inbox")?.addEventListener("click", () => {
    closeAlertReport();
  });
  loadAlertEvidence(alert);
}

async function loadAlertEvidence(alert) {
  const box = document.querySelector("#alert-evidence");
  if (!box) {
    return;
  }
  const deviceIp = alert.subject ? String(alert.subject) : "";
  if (!deviceIp) {
    box.innerHTML = '<div class="empty">No device IP on this alert, so domain evidence is unavailable.</div>';
    return;
  }
  const params = alertEvidenceParams(alert);
  try {
    const query = new URLSearchParams({
      client: deviceIp,
      window: String(params.windowSeconds),
      until: String(params.until),
      focus: params.focus,
      limit: "50",
    });
    const evidence = await getJson(`/api/alerts/evidence?${query.toString()}`);
    renderAlertEvidence(box, evidence, params.focus);
  } catch (error) {
    box.innerHTML = `<div class="empty">Could not load domains: ${escapeHtml(error.message)}</div>`;
  }
}

function renderAlertEvidence(container, evidence, focus) {
  const domains = evidence.domains || [];
  const totals = evidence.totals || {};
  if (!domains.length) {
    container.innerHTML = `
      <div class="empty">
        No matching DNS domains found in that window
        (${escapeHtml(String(totals.queries || 0))} queries · ${escapeHtml(String(totals.blocked || 0))} blocked).
        The lookups may have aged out of Pi-hole’s short-term query log.
      </div>
    `;
    return;
  }
  const heading =
    focus === "blocked"
      ? `Domains involved (${domains.length} shown · ${totals.blocked || 0} blocked lookups)`
      : `Top domains (${domains.length} shown · ${totals.queries || 0} lookups)`;
  container.innerHTML = `
    <div class="section-title" style="margin-top: 12px">
      <h2>${escapeHtml(heading)}</h2>
    </div>
    <div class="alert-domain-list" id="alert-domain-list"></div>
  `;
  const list = container.querySelector("#alert-domain-list");
  domains.forEach((row) => {
    const item = document.createElement("div");
    item.className = `alert-domain-row ${row.blocked ? "was-blocked" : "was-allowed"}`;
    const statusLabel = row.blocked
      ? `Blocked ×${row.blockedHits || row.hits || 0}`
      : `Allowed ×${row.allowedHits || row.hits || 0}`;
    item.innerHTML = `
      <div class="alert-domain-copy">
        <strong class="alert-domain-name">${escapeHtml(row.domain)}</strong>
        <span class="device-card-meta">${escapeHtml(row.service || "Domain")} · ${escapeHtml(
          row.category || "other"
        )} · ${escapeHtml(statusLabel)}</span>
      </div>
      <div class="alert-domain-actions">
        ${
          row.blocked
            ? '<span class="alert-read-tag">Already blocked</span>'
            : `<button class="danger-button compact" type="button" data-block-domain="${escapeAttribute(
                row.domain
              )}">Block domain</button>`
        }
      </div>
    `;
    item.querySelector("[data-block-domain]")?.addEventListener("click", async (event) => {
      const button = event.currentTarget;
      const domain = button.dataset.blockDomain;
      if (!domain || state.busy) {
        return;
      }
      button.disabled = true;
      try {
        await postJson("/api/pihole/deny", { domain, action: "add" });
        showStatus(`Blocked ${domain}`, "good");
        const tag = document.createElement("span");
        tag.className = "alert-read-tag";
        tag.textContent = "Added to blocklist";
        button.replaceWith(tag);
        item.classList.remove("was-allowed");
        item.classList.add("was-blocked");
      } catch (error) {
        button.disabled = false;
        showStatus(error.message, "bad");
      }
    });
    list?.appendChild(item);
  });
}

function renderAlertBadge() {
  if (!elements.alertBadge) {
    return;
  }
  const count = state.unackedAlerts || 0;
  elements.alertBadge.textContent = String(count);
  elements.alertBadge.classList.toggle("hidden", count <= 0);
}

function renderSetupBanner() {
  if (!elements.setupBanner || !state.setup) {
    return;
  }
  const dismissed = window.sessionStorage.getItem("pi-circle-setup-dismissed") === "1";
  if (state.setup.ready && dismissed) {
    elements.setupBanner.classList.add("hidden");
    return;
  }
  const checks = state.setup.checks || [];
  const failed = checks.filter((check) => !check.ok && check.id !== "linked_devices");
  elements.setupBanner.classList.remove("hidden");
  elements.setupBanner.innerHTML = `
    <div>
      <strong>${state.setup.ready ? "Setup looks good" : "Finish setup"}</strong>
      <p class="device-card-meta">${escapeHtml((state.setup.tips || [])[0] || "")}</p>
      <div class="setup-checks">
        ${checks
          .map(
            (check) =>
              `<span class="setup-check ${check.ok ? "ok" : "bad"}">${escapeHtml(check.label)}</span>`
          )
          .join("")}
      </div>
    </div>
    <button class="secondary-button compact" type="button" id="dismiss-setup">${
      failed.length ? "Hide for now" : "Dismiss"
    }</button>
  `;
  elements.setupBanner.querySelector("#dismiss-setup")?.addEventListener("click", () => {
    window.sessionStorage.setItem("pi-circle-setup-dismissed", "1");
    elements.setupBanner.classList.add("hidden");
  });
}

function renderBandwidthList(rows) {
  if (!elements.bandwidthList) {
    return;
  }
  if (!rows.length) {
    elements.bandwidthList.innerHTML = '<div class="empty">Link a device to measure on-path bandwidth.</div>';
    return;
  }
  elements.bandwidthList.innerHTML = "";
  rows.forEach((row) => {
    const device = state.devices.find((item) => item.ip_address === row.ip_address);
    const item = document.createElement("button");
    item.type = "button";
    item.className = "rank-row";
    item.innerHTML = `
      <span>${escapeHtml(device ? displayName(device) : row.ip_address)}</span>
      <strong>${escapeHtml(formatBytesPerSec(row.bytesPerSec || 0))}${
        row.connections ? ` · ${escapeHtml(String(row.connections))} flows` : ""
      }</strong>
    `;
    item.addEventListener("click", () => openDevicePage(row.ip_address));
    elements.bandwidthList.appendChild(item);
  });
}

async function loadOnpathFlows() {
  if (!elements.onpathFlows) {
    return;
  }
  try {
    const payload = await getJson("/api/connections?limit=12");
    renderOnpathFlows(payload.devices || []);
  } catch (error) {
    elements.onpathFlows.innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
  }
}

function renderOnpathFlows(devices) {
  if (!elements.onpathFlows) {
    return;
  }
  if (!devices.length) {
    elements.onpathFlows.innerHTML = '<div class="empty">Link a device to inspect live L4 flows.</div>';
    return;
  }
  elements.onpathFlows.innerHTML = "";
  devices.forEach((device) => {
    const card = document.createElement("button");
    card.type = "button";
    card.className = "onpath-card";
    const remotes = (device.topRemotes || [])
      .slice(0, 3)
      .map((row) => escapeHtml(row.host || row.remote))
      .join(", ");
    const protos = (device.protocols || [])
      .slice(0, 3)
      .map((row) => `${String(row.protocol || "?").toUpperCase()}:${row.flows}`)
      .join(" · ");
    card.innerHTML = `
      <strong>${escapeHtml(device.name || device.ip)}</strong>
      <span>${escapeHtml(formatBytesPerSec(device.bandwidth?.bytesPerSec || 0))} · ${escapeHtml(
        String(device.flowCount || 0)
      )} flows</span>
      <span class="onpath-meta">${escapeHtml(protos || "No active flows")}</span>
      <span class="onpath-meta">${remotes ? escapeHtml(remotes) : "—"}</span>
    `;
    card.addEventListener("click", () => openDevicePage(device.ip));
    elements.onpathFlows.appendChild(card);
  });
}

async function reloadActivity(reset) {
  if (reset) {
    state.activityLatestId = 0;
    state.activityEvents = [];
  }
  try {
    const params = new URLSearchParams({
      limit: "100",
      since_id: String(reset ? 0 : state.activityLatestId),
    });
    if (state.filters.client) params.set("client", state.filters.client);
    if (state.filters.category) params.set("category", state.filters.category);
    if (state.filters.status) params.set("status", state.filters.status);
    if (state.filters.q) params.set("q", state.filters.q);
    const payload = await getJson(`/api/activity/live?${params}`);
    if (reset) {
      state.activityEvents = payload.events || [];
    } else if (payload.events?.length) {
      state.activityEvents = [...state.activityEvents, ...payload.events].slice(-200);
    }
    state.activityLatestId = payload.latestId || state.activityLatestId;
    renderActivityFeed();
  } catch (error) {
    if (elements.activityFeed) {
      elements.activityFeed.innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
    }
  }
}

function renderActivityFeed() {
  if (!elements.activityFeed) {
    return;
  }
  if (!state.activityEvents.length) {
    elements.activityFeed.innerHTML = '<div class="empty">No matching activity yet.</div>';
    return;
  }
  const collapsed = collapseEvents(state.activityEvents);
  elements.activityFeed.innerHTML = "";
  collapsed
    .slice()
    .reverse()
    .forEach((event) => {
      const card = document.createElement("article");
      card.className = `live-card ${event.blocked ? "blocked" : ""} ${event.category || ""}`;
      card.innerHTML = `
        <div class="live-card-time">${escapeHtml(formatEventTime(event.timestamp))}</div>
        <div class="live-card-main">
          <p class="live-card-device">${escapeHtml(event.device_name || event.client_ip)}</p>
          <p class="live-card-headline">${escapeHtml(event.headline || event.service || event.domain)}</p>
          <p class="live-card-detail">${escapeHtml(event.detail || event.domain || "")}</p>
        </div>
        <div class="live-card-meta">
          <span class="live-status ${event.blocked ? "blocked" : event.status}">${escapeHtml(event.blocked ? "Blocked" : event.status)}</span>
          ${event.count > 1 ? `<span class="live-repeat">×${event.count}</span>` : ""}
        </div>
      `;
      card.addEventListener("click", () => openDevicePage(event.client_ip));
      elements.activityFeed.appendChild(card);
    });
}

async function loadDevicePage(ipAddress, showBusy) {
  try {
    if (showBusy) {
      if (elements.deviceTitle) {
        elements.deviceTitle.textContent = ipAddress;
      }
      if (elements.deviceEyebrow) {
        elements.deviceEyebrow.textContent = "Loading device report…";
      }
      elements.deviceLiveFeed.innerHTML = '<div class="empty">Loading live activity…</div>';
      elements.deviceSearchFeed.innerHTML = '<div class="empty">Loading searches…</div>';
    }
    const page = await getJson(`/api/devices/${encodeURIComponent(ipAddress)}/page?limit=100`);
    if (state.selectedIp !== ipAddress) {
      return;
    }
    state.devicePage = page;
    renderDevicePage();
  } catch (error) {
    if (state.selectedIp === ipAddress) {
      if (elements.deviceTitle) {
        elements.deviceTitle.textContent = ipAddress;
      }
      if (elements.deviceEyebrow) {
        elements.deviceEyebrow.textContent = "Device report unavailable";
      }
      if (elements.deviceDnsBanner) {
        elements.deviceDnsBanner.classList.remove("hidden");
        elements.deviceDnsBanner.textContent =
          "Could not load this device report. It may have left the network, or the IP in the alert is no longer in inventory.";
      }
      elements.deviceLiveFeed.innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
      showStatus(error.message, "bad");
    }
  }
}

function renderDevicePage() {
  const page = state.devicePage;
  if (!page?.device) {
    return;
  }
  const device = page.device;
  elements.deviceTitle.textContent = displayName(device);
  elements.deviceEyebrow.textContent = [device.vendor, typeLabel(effectiveDeviceType(device))].filter(Boolean).join(" · ") || "Device";
  const linked = Boolean(page.linked || isTargeted(device) || isEnrolled(device));
  const policy = page.policy || {};
  const stateLabel = isGateway(device)
    ? "Router"
    : policy.blocked
      ? policy.blockReason === "bedtime"
        ? "Bedtime"
        : policy.blockReason === "daily_limit"
          ? "Daily limit"
          : "Paused"
      : linked
        ? "Linked"
        : "Online";
  elements.deviceState.textContent = stateLabel;
  elements.deviceState.className = `state ${policy.blocked || device.paused ? "paused" : linked ? "linked" : ""}`;
  const liveEvents = page.live || [];
  const dnsAge = page.dnsAgeSeconds;
  const dnsSilent = Boolean(page.dnsSilent);
  elements.deviceLivePulse?.classList.toggle("idle", dnsSilent || !liveEvents.length);
  if (elements.deviceDnsBanner) {
    if (policy.blocked) {
      elements.deviceDnsBanner.classList.remove("hidden");
      elements.deviceDnsBanner.innerHTML = `Internet blocked (${escapeHtml(policy.blockReason || "policy")}). ${
        policy.blockReason === "bedtime"
          ? `Bedtime ${escapeHtml(policy.bedtimeStart || "")}–${escapeHtml(policy.bedtimeEnd || "")}.`
          : policy.blockReason === "daily_limit"
            ? `Used ${policy.usedMinutes || 0}/${policy.dailyMinutes || 0} minutes today.`
            : "Tap Resume to restore access."
      }`;
    } else if (policy.requiresLink) {
      elements.deviceDnsBanner.classList.remove("hidden");
      elements.deviceDnsBanner.innerHTML =
        "Pause/schedule is saved. This device must be <strong>Linked</strong> before Pi-Circle can enforce an internet pause; otherwise protection is DNS-level only.";
    } else if (dnsSilent) {
      elements.deviceDnsBanner.classList.remove("hidden");
      elements.deviceDnsBanner.innerHTML = linked
        ? `No DNS seen for ${escapeHtml(formatAge(dnsAge))}. Private DNS / Secure DNS may still be on — toggle airplane mode once so apps fall back to Pi-Circle.`
        : `No DNS seen for ${escapeHtml(formatAge(dnsAge))}. Link this device (or turn off Private DNS) so lookups show here.`;
    } else {
      elements.deviceDnsBanner.classList.add("hidden");
      elements.deviceDnsBanner.textContent = "";
    }
  }

  const totals = page.stats?.totals || {};
  if (elements.deviceStatsStrip) {
    const bw = page.bandwidth;
    elements.deviceStatsStrip.innerHTML = [
      metricCard("Last DNS", formatAge(dnsAge)),
      metricCard("Queries/hr", formatCompact(totals.queries || 0)),
      metricCard("Blocked", `${totals.blockedPercent ?? 0}%`),
      metricCard("Bandwidth", bw ? formatBytesPerSec(bw.bytesPerSec || 0) : linked ? "Sampling…" : "Link to measure"),
      metricCard("Flows", linked ? String(page.flowCount ?? (page.connections || []).length) : "—"),
    ].join("");
  }
  renderTrafficChart(elements.deviceHistoryChart, page.history?.series || []);
  renderTrafficChart(elements.deviceTrafficChart, page.series || []);
  renderBandwidthChart(elements.deviceBandwidthChart, page.bandwidthSeries || [], linked);
  renderProtocolChips(elements.deviceProtocolChips, page.protocols || [], linked);
  renderEventCards(
    elements.deviceLiveFeed,
    liveEvents,
    dnsSilent
      ? "Waiting for DNS… open a website or app, or disable Private DNS on the phone."
      : "No live activity yet for this device."
  );
  renderSearchCards(elements.deviceSearchFeed, page.searches || []);
  renderServices(elements.deviceServices, page.topServices || []);
  renderTopRemotes(elements.deviceTopRemotes, page.topRemotes || [], linked);
  renderConnections(elements.deviceConnections, page.connections || [], linked);
  renderDeviceInfo();
}

function renderConnections(container, connections, linked) {
  if (!container) {
    return;
  }
  if (!linked) {
    container.innerHTML = '<div class="empty">Link this device to inspect active connections.</div>';
    return;
  }
  if (!connections.length) {
    container.innerHTML = '<div class="empty">No active flows right now.</div>';
    return;
  }
  container.innerHTML = "";
  connections.forEach((row) => {
    const item = document.createElement("div");
    item.className = "connection-row";
    const host = row.host ? `${row.host} · ` : "";
    item.innerHTML = `
      <strong>${escapeHtml(row.protocol?.toUpperCase() || "?")} ${escapeHtml(row.remote || "")}:${escapeHtml(String(row.remotePort || ""))}</strong>
      <span>${escapeHtml(host)}${escapeHtml(row.serviceHint || "")} · ${escapeHtml(row.direction || "")} · ${escapeHtml(formatBytes(row.bytes || 0))}</span>
    `;
    container.appendChild(item);
  });
}

function renderTopRemotes(container, remotes, linked) {
  if (!container) {
    return;
  }
  if (!linked) {
    container.innerHTML = '<div class="empty">Link this device to rank remote hosts.</div>';
    return;
  }
  if (!remotes.length) {
    container.innerHTML = '<div class="empty">No remote peers yet.</div>';
    return;
  }
  renderRankList(
    container,
    remotes,
    (row) => row.host || row.remote,
    (row) => `${formatBytes(row.bytes || 0)} · ${row.flows || 0} flows`,
    null
  );
}

function renderProtocolChips(container, protocols, linked) {
  if (!container) {
    return;
  }
  if (!linked) {
    container.innerHTML = "";
    return;
  }
  if (!protocols.length) {
    container.innerHTML = '<div class="empty">Waiting for L4 flows…</div>';
    return;
  }
  container.innerHTML = protocols
    .map(
      (row) =>
        `<span class="service-chip proto-${escapeHtml(String(row.protocol || "other").toLowerCase())}">${escapeHtml(
          String(row.protocol || "?").toUpperCase()
        )} · ${escapeHtml(String(row.flows || 0))} · ${escapeHtml(formatBytes(row.bytes || 0))}</span>`
    )
    .join("");
}

function renderBandwidthChart(container, series, linked) {
  if (!container) {
    return;
  }
  if (!linked) {
    container.innerHTML = '<div class="empty">Link this device to measure throughput.</div>';
    return;
  }
  if (!series.length) {
    container.innerHTML = '<div class="empty">Collecting throughput samples…</div>';
    return;
  }
  const width = 720;
  const height = 120;
  const pad = 18;
  const maxRate = Math.max(1, ...series.map((row) => Number(row.bytesPerSec) || 0));
  const points = seriesToPoints(series, width, height, pad, (row) => Number(row.bytesPerSec) || 0, maxRate);
  const uid = `bw-${container.id || "chart"}-${Math.random().toString(36).slice(2, 7)}`;
  container.innerHTML = buildGlassChartSvg({
    width,
    height,
    pad,
    points,
    lineColor: "#4cd7f6",
    glowColor: "#4cd7f6",
    fillId: `${uid}-fill`,
    glowId: `${uid}-glow`,
    className: "traffic-svg bandwidth-svg glass-chart",
  });
  container.insertAdjacentHTML(
    "beforeend",
    `<div class="chart-caption">Peak ${escapeHtml(formatBytesPerSec(maxRate))}</div>`
  );
}

function renderEventCards(container, events, emptyText) {
  if (!container) {
    return;
  }
  if (!events.length) {
    container.innerHTML = `<div class="empty">${escapeHtml(emptyText)}</div>`;
    return;
  }
  const collapsed = collapseEvents(events);
  container.innerHTML = "";
  collapsed
    .slice()
    .reverse()
    .forEach((event) => {
      const card = document.createElement("article");
      card.className = `live-card ${event.blocked ? "blocked" : ""} ${event.category || ""}`;
      card.innerHTML = `
        <div class="live-card-time">${escapeHtml(formatAge(Math.max(0, Math.floor(Date.now() / 1000) - Number(event.timestamp || 0))))}<br/><span class="live-card-clock">${escapeHtml(formatEventTime(event.timestamp))}</span></div>
        <div class="live-card-main">
          <p class="live-card-headline">${escapeHtml(event.headline || event.service || event.domain)}</p>
          <p class="live-card-detail">${escapeHtml(event.detail || event.domain || "")}</p>
        </div>
        <div class="live-card-meta">
          <span class="live-status ${event.blocked ? "blocked" : event.status}">${escapeHtml(event.blocked ? "Blocked" : event.status)}</span>
          ${event.count > 1 ? `<span class="live-repeat">×${event.count}</span>` : ""}
        </div>
      `;
      container.appendChild(card);
    });
}

function renderSearchCards(container, searches) {
  if (!container) {
    return;
  }
  if (!searches.length) {
    container.innerHTML =
      '<div class="empty">No visible searches yet. Encrypted Google/Bing queries usually appear as “[searching: Google]”.</div>';
    return;
  }
  container.innerHTML = "";
  searches
    .slice()
    .reverse()
    .forEach((event) => {
      const row = document.createElement("article");
      row.className = "search-card";
      const phrase = event.search_query ? `[searched: ${event.search_query}]` : event.headline || `[searching: ${event.service}]`;
      row.innerHTML = `
        <p class="search-phrase">${escapeHtml(phrase)}</p>
        <p class="device-card-meta">${escapeHtml(formatEventTime(event.timestamp))} · ${escapeHtml(event.service || "Search")} · ${escapeHtml(event.domain || "")}</p>
      `;
      container.appendChild(row);
    });
}

function renderServices(container, services) {
  if (!container) {
    return;
  }
  if (!services.length) {
    container.innerHTML = '<div class="empty">No service summary yet.</div>';
    return;
  }
  container.innerHTML = "";
  services.forEach((item) => {
    const chip = document.createElement("div");
    chip.className = "service-chip";
    chip.innerHTML = `<span>${escapeHtml(item.service)}</span><strong>${item.count}</strong>`;
    container.appendChild(chip);
  });
}

function renderDeviceInfo() {
  if (!elements.deviceInfo || !state.devicePage?.device) {
    return;
  }
  const device = state.devicePage.device;
  const type = effectiveDeviceType(device);
  const bw = state.devicePage.bandwidth;
  const policy = state.devicePage.policy || {};
  const paused = Boolean(device.paused);
  elements.deviceInfo.innerHTML = `
    <div class="info-grid">
      <div><span class="field-label">IP</span><strong>${escapeHtml(device.ip_address)}</strong></div>
      <div><span class="field-label">MAC</span><strong>${escapeHtml(device.mac_address || "Unknown")}</strong></div>
      <div><span class="field-label">Vendor</span><strong>${escapeHtml(device.vendor || "Unknown")}</strong></div>
      <div><span class="field-label">Hostname</span><strong>${escapeHtml(device.hostname || "Unknown")}</strong></div>
      <div><span class="field-label">Today</span><strong>${escapeHtml(
        policy.dailyMinutes ? `${policy.usedMinutes || 0}/${policy.dailyMinutes} min` : "No limit"
      )}</strong></div>
      <div><span class="field-label">Bandwidth</span><strong>${escapeHtml(bw ? formatBytesPerSec(bw.bytesPerSec || 0) : "—")}</strong></div>
    </div>
    <div class="action-row" style="margin-top: 4px">
      <button class="${paused ? "primary-button" : "danger-button"}" type="button" id="info-pause">
        ${paused ? "Resume" : isEnrolled(device) || isTargeted(device) ? "Pause Internet" : "Save Pause Rule"}
      </button>
      <button class="${isEnrolled(device) || isTargeted(device) ? "secondary-button" : "primary-button"}" type="button" id="info-link">
        ${isGateway(device) ? "Router" : isEnrolled(device) || isTargeted(device) ? "Unlink" : "Link"}
      </button>
    </div>
    <p class="device-card-meta">${escapeHtml(deviceCapabilityLabel(device))}</p>
    <p class="field-label" style="margin-top: 12px">Quick label</p>
    <div class="action-row" id="quick-labels"></div>
    <label class="field-label" for="info-name">Display name</label>
    <input class="name-input" id="info-name" maxlength="80" value="${escapeAttribute(device.display_name || "")}" />
    <label class="field-label" for="info-type">Device type</label>
    <select class="type-select" id="info-type"></select>
    <label class="field-label" for="info-profile">Profile</label>
    <select class="type-select" id="info-profile"></select>
    <div class="action-row" style="margin-top: 10px">
      <button class="secondary-button" type="button" id="info-save">Save identity</button>
    </div>
  `;
  const typeSelect = elements.deviceInfo.querySelector("#info-type");
  DEVICE_TYPES.forEach(([value, label]) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = label;
    option.selected = type === value;
    typeSelect.appendChild(option);
  });
  if (isGateway(device)) {
    typeSelect.value = "router";
    typeSelect.disabled = true;
  }
  const profileSelect = elements.deviceInfo.querySelector("#info-profile");
  const none = document.createElement("option");
  none.value = "";
  none.textContent = "No profile";
  none.selected = !device.profile_id;
  profileSelect.appendChild(none);
  state.profiles.forEach((profile) => {
    const option = document.createElement("option");
    option.value = String(profile.id);
    option.textContent = profile.name;
    option.selected = device.profile_id === profile.id;
    profileSelect.appendChild(option);
  });
  const quick = elements.deviceInfo.querySelector("#quick-labels");
  [
    ["My phone", "iphone"],
    ["Kid tablet", "ipad"],
    ["Android", "android"],
    ["Laptop", "laptop"],
    ["TV", "tv"],
  ].forEach(([label, deviceType]) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "secondary-button compact";
    button.textContent = label;
    button.addEventListener("click", () => {
      const nameInput = elements.deviceInfo.querySelector("#info-name");
      const typeEl = elements.deviceInfo.querySelector("#info-type");
      if (nameInput && !nameInput.value.trim()) {
        nameInput.value = label;
      }
      if (typeEl) {
        typeEl.value = deviceType;
      }
      saveDeviceIdentity(device);
    });
    quick?.appendChild(button);
  });
  elements.deviceInfo.querySelector("#info-save")?.addEventListener("click", () => saveDeviceIdentity(device));
  elements.deviceInfo.querySelector("#info-profile")?.addEventListener("change", (event) => {
    saveDeviceProfile(device, event.target.value);
  });
  elements.deviceInfo.querySelector("#info-pause")?.addEventListener("click", () => {
    if (isGateway(device)) {
      return;
    }
    setDevicePaused(device, !paused);
  });
  const link = elements.deviceInfo.querySelector("#info-link");
  if (link) {
    link.disabled = isGateway(device) || state.busy;
    link.addEventListener("click", () => setDeviceTarget(device, !(isEnrolled(device) || isTargeted(device))));
  }
  const pauseBtn = elements.deviceInfo.querySelector("#info-pause");
  if (pauseBtn) {
    pauseBtn.disabled = isGateway(device) || state.busy;
  }
}

function seriesToPoints(series, width, height, pad, valueFn, maxValue) {
  const step = (width - pad * 2) / Math.max(1, series.length - 1);
  const chartHeight = height - pad * 2;
  return series.map((row, index) => {
    const x = pad + index * step;
    const ratio = Math.max(0, Math.min(1, (valueFn(row) || 0) / maxValue));
    const y = height - pad - ratio * chartHeight;
    return { x, y };
  });
}

function smoothLinePath(points) {
  if (!points.length) {
    return "";
  }
  if (points.length === 1) {
    return `M ${points[0].x} ${points[0].y}`;
  }
  if (points.length === 2) {
    return `M ${points[0].x} ${points[0].y} L ${points[1].x} ${points[1].y}`;
  }
  let path = `M ${points[0].x} ${points[0].y}`;
  for (let i = 0; i < points.length - 1; i += 1) {
    const p0 = points[i === 0 ? i : i - 1];
    const p1 = points[i];
    const p2 = points[i + 1];
    const p3 = points[i + 2] || p2;
    const cp1x = p1.x + (p2.x - p0.x) / 6;
    const cp1y = p1.y + (p2.y - p0.y) / 6;
    const cp2x = p2.x - (p3.x - p1.x) / 6;
    const cp2y = p2.y - (p3.y - p1.y) / 6;
    path += ` C ${cp1x} ${cp1y}, ${cp2x} ${cp2y}, ${p2.x} ${p2.y}`;
  }
  return path;
}

function smoothAreaPath(points, height, pad) {
  if (!points.length) {
    return "";
  }
  const line = smoothLinePath(points);
  const last = points[points.length - 1];
  const first = points[0];
  const base = height - pad;
  return `${line} L ${last.x} ${base} L ${first.x} ${base} Z`;
}

function chartGridLines(width, height, pad, rows = 4) {
  const lines = [];
  for (let i = 0; i <= rows; i += 1) {
    const y = pad + ((height - pad * 2) * i) / rows;
    lines.push(
      `<line class="chart-grid-line" x1="${pad}" y1="${y}" x2="${width - pad}" y2="${y}"></line>`
    );
  }
  return lines.join("");
}

function buildGlassChartSvg({
  width,
  height,
  pad,
  points,
  lineColor,
  glowColor,
  fillId,
  glowId,
  className,
  blockedBars = "",
}) {
  const linePath = smoothLinePath(points);
  const areaPath = smoothAreaPath(points, height, pad);
  return `
    <svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" class="${className}">
      <defs>
        <linearGradient id="${fillId}" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="${lineColor}" stop-opacity="0.42"></stop>
          <stop offset="55%" stop-color="${lineColor}" stop-opacity="0.12"></stop>
          <stop offset="100%" stop-color="${lineColor}" stop-opacity="0"></stop>
        </linearGradient>
        <linearGradient id="${fillId}Bar" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#ff6b7a" stop-opacity="0.95"></stop>
          <stop offset="100%" stop-color="#cc3344" stop-opacity="0.35"></stop>
        </linearGradient>
        <filter id="${glowId}" x="-40%" y="-40%" width="180%" height="180%">
          <feGaussianBlur stdDeviation="2.4" result="blur"></feGaussianBlur>
          <feMerge>
            <feMergeNode in="blur"></feMergeNode>
            <feMergeNode in="SourceGraphic"></feMergeNode>
          </feMerge>
        </filter>
      </defs>
      <rect class="chart-plot-bg" x="0" y="0" width="${width}" height="${height}"></rect>
      ${chartGridLines(width, height, pad)}
      <path class="chart-area" d="${areaPath}" fill="url(#${fillId})"></path>
      ${blockedBars}
      <path class="chart-line-glow" d="${linePath}" fill="none" stroke="${glowColor}" stroke-width="6" stroke-linecap="round" stroke-linejoin="round" opacity="0.35" filter="url(#${glowId})"></path>
      <path class="chart-line" d="${linePath}" fill="none" stroke="${lineColor}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" filter="url(#${glowId})"></path>
    </svg>
  `;
}

function renderTrafficChart(container, series) {
  if (!container) {
    return;
  }
  if (!series.length) {
    container.innerHTML = '<div class="empty">No traffic in this window.</div>';
    return;
  }
  const width = 720;
  const height = container.classList.contains("short") ? 120 : 180;
  const pad = 18;
  const maxQueries = Math.max(
    1,
    ...series.map((row) => Math.max(Number(row.queries) || 0, Number(row.blocked) || 0))
  );
  const points = seriesToPoints(series, width, height, pad, (row) => Number(row.queries) || 0, maxQueries);
  const step = (width - pad * 2) / Math.max(1, series.length - 1);
  const barWidth = Math.max(3, Math.min(8, step * 0.35));
  const blockedBars = series
    .map((row, index) => {
      const value = Number(row.blocked) || 0;
      if (!value) {
        return "";
      }
      const barHeight = Math.max(2, (value / maxQueries) * (height - pad * 2));
      const x = pad + index * step - barWidth / 2;
      const y = height - pad - barHeight;
      const radius = Math.min(3, barWidth / 2);
      return `<rect class="chart-block-bar" x="${x}" y="${y}" width="${barWidth}" height="${barHeight}" rx="${radius}" ry="${radius}" fill="url(#trafficFillBar)"></rect>`;
    })
    .join("");
  const uid = `tr-${container.id || "chart"}-${Math.random().toString(36).slice(2, 7)}`;
  const bars = blockedBars.replaceAll("url(#trafficFillBar)", `url(#${uid}-fillBar)`);
  container.innerHTML = buildGlassChartSvg({
    width,
    height,
    pad,
    points,
    lineColor: "#ffb24d",
    glowColor: "#ff9900",
    fillId: `${uid}-fill`,
    glowId: `${uid}-glow`,
    className: "traffic-svg glass-chart",
    blockedBars: bars,
  });
}

function renderRankList(container, rows, labelFn, countFn, onClick) {
  if (!container) {
    return;
  }
  if (!rows.length) {
    container.innerHTML = '<div class="empty">No data yet.</div>';
    return;
  }
  container.innerHTML = "";
  rows.forEach((row) => {
    const item = document.createElement(onClick ? "button" : "div");
    if (onClick) {
      item.type = "button";
      item.addEventListener("click", () => onClick(row));
    }
    item.className = "rank-row";
    item.innerHTML = `<span>${escapeHtml(String(labelFn(row)))}</span><strong>${escapeHtml(String(countFn(row)))}</strong>`;
    container.appendChild(item);
  });
}

function metricCard(label, value) {
  return `<div class="metric compact"><span class="metric-label">${escapeHtml(label)}</span><strong>${escapeHtml(String(value))}</strong></div>`;
}

function formatGravityUpdateSummary(update) {
  const status = update || {};
  if (status.installed === false) {
    return "Not installed";
  }
  if (status.enabled === false) {
    return "Off";
  }
  if (status.active === false) {
    return "Paused";
  }
  return `Every ${status.intervalHours || 48}h`;
}

function formatGravityUpdateDetail(update) {
  const status = update || {};
  const summary = formatGravityUpdateSummary(status);
  const result = status.lastResult && status.lastResult !== "unknown" ? `Last result: ${status.lastResult}` : "";
  return result ? `${summary} · ${result}` : summary;
}

function collapseEvents(events) {
  const collapsed = [];
  events.forEach((event) => {
    const previous = collapsed[collapsed.length - 1];
    const headline = event.headline || event.service || event.domain;
    const same =
      previous &&
      previous.headline === headline &&
      previous.client_ip === event.client_ip &&
      previous.status === event.status &&
      event.timestamp - previous.timestamp <= 20;
    if (same) {
      previous.count += 1;
      previous.timestamp = event.timestamp;
      return;
    }
    collapsed.push({ ...event, headline, count: 1 });
  });
  return collapsed;
}

function startDevicePolling() {
  stopDevicePolling();
  state.deviceTimer = window.setInterval(() => {
    if (state.selectedIp) {
      loadDevicePage(state.selectedIp, false);
    }
  }, 1000);
}

function stopDevicePolling() {
  if (state.deviceTimer) {
    window.clearInterval(state.deviceTimer);
    state.deviceTimer = null;
  }
}

function startActivityPolling() {
  stopActivityPolling();
  state.activityTimer = window.setInterval(() => {
    loadHistory();
    reloadActivity(false);
    loadAlerts();
    loadOnpathFlows();
  }, 2500);
}

function stopActivityPolling() {
  if (state.activityTimer) {
    window.clearInterval(state.activityTimer);
    state.activityTimer = null;
  }
}

function renderDnsPanel() {
  const pihole = state.pihole || {};
  const health = state.health || {};
  if (elements.piholeAdminLink) {
    const host = window.location.hostname || "pi.hole";
    elements.piholeAdminLink.href = `http://${host}/admin/`;
  }
  const blocking =
    pihole.blocking_enabled === true ? "On" : pihole.blocking_enabled === false ? "Off" : "—";
  if (elements.dnsStatsStrip) {
    elements.dnsStatsStrip.innerHTML = [
      metricCard("Blocking", blocking),
      metricCard("Adlists", formatNumber(pihole.enabled_adlists || pihole.enabledAdlists || 0)),
      metricCard("Gravity", formatCompact(pihole.gravity_domains || pihole.gravityDomains || 0)),
      metricCard("Domain rules", formatNumber(pihole.domainlist_entries || pihole.domainlistEntries || 0)),
      metricCard("Auto update", formatGravityUpdateSummary(pihole.gravity_update || pihole.gravityUpdate)),
    ].join("");
  }
  if (elements.dnsEngine) {
    elements.dnsEngine.innerHTML = `
      <div><span class="field-label">Engine</span><strong>Pi-hole</strong></div>
      <div><span class="field-label">Core</span><strong>${escapeHtml(pihole.core_version || pihole.coreVersion || "—")}</strong></div>
      <div><span class="field-label">FTL</span><strong>${escapeHtml(pihole.ftl_version || pihole.ftlVersion || "—")}</strong></div>
      <div><span class="field-label">Web</span><strong>${escapeHtml(pihole.web_version || pihole.webVersion || "—")}</strong></div>
    `;
  }
  if (elements.dnsProtection) {
    elements.dnsProtection.innerHTML = `
      <div><span class="field-label">Groups</span><strong>${escapeHtml(String(pihole.groups ?? "—"))}</strong></div>
      <div><span class="field-label">Clients seen</span><strong>${escapeHtml(String(pihole.clients ?? "—"))}</strong></div>
      <div><span class="field-label">Privacy shield</span><strong>DoH + telemetry denylist</strong></div>
      <div><span class="field-label">Pi-hole lists</span><strong>${escapeHtml(formatGravityUpdateDetail(pihole.gravity_update || pihole.gravityUpdate))}</strong></div>
      <div><span class="field-label">Mode</span><strong>${escapeHtml(health.mode || state.config?.mode || "—")}</strong></div>
    `;
  }
  renderProtectionDatabase();
  renderPiholeStatus();
}

async function loadProtectionDatabase() {
  if (!elements.protectionDbSummary && !elements.blocklistTable) {
    return;
  }
  try {
    const [databasePayload, blocklistPayload] = await Promise.all([
      getJson("/api/protection/database"),
      getJson("/api/protection/blocklists?limit=75"),
    ]);
    state.protectionDatabase = databasePayload.summary || null;
    state.blocklists = blocklistPayload.blocklists || [];
    renderProtectionDatabase();
  } catch (error) {
    if (elements.protectionDbSummary) {
      elements.protectionDbSummary.innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
    }
    if (elements.blocklistTable) {
      elements.blocklistTable.innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
    }
  }
}

function renderProtectionDatabase() {
  const summary = state.protectionDatabase;
  if (elements.protectionDbSummary) {
    if (!summary) {
      elements.protectionDbSummary.innerHTML = '<div class="empty">Protection database summary has not loaded yet.</div>';
    } else if (!summary.available) {
      elements.protectionDbSummary.innerHTML = `<div class="empty">${escapeHtml(summary.error || "Pi-hole gravity database is unavailable.")}</div>`;
    } else {
      elements.protectionDbSummary.innerHTML = [
        metricCard("Active entries", formatCompact(summary.total_active_entries || summary.totalActiveEntries || 0)),
        metricCard("Unique domains", formatOptionalCompact(summary.domain_count ?? summary.domainCount)),
        metricCard("Sources", formatNumber(summary.list_source_count || summary.listSourceCount || 0)),
        metricCard("Duplicates", formatOptionalCompact(summary.duplicate_count ?? summary.duplicateCount)),
        metricCard("Manual rules", formatNumber(summary.domain_rule_count || summary.domainRuleCount || 0)),
        metricCard("Updated", formatEpochDate(summary.last_modified || summary.lastModified)),
      ].join("");
    }
  }
  renderBlocklists();
}

function renderBlocklists() {
  if (!elements.blocklistTable) {
    return;
  }
  if (!state.blocklists.length) {
    elements.blocklistTable.innerHTML = '<div class="empty">No blocklist sources reported by Pi-hole.</div>';
    return;
  }
  const rows = state.blocklists
    .slice(0, 75)
    .map(
      (row) => `
        <div class="blocklist-row">
          <div>
            <strong>${escapeHtml(blocklistName(row.address))}</strong>
            <p class="device-card-meta">${escapeHtml(row.address || "No source URL")}</p>
          </div>
          <span class="state ${row.enabled ? "good" : "warn"}">${row.enabled ? "Enabled" : "Disabled"}</span>
          <span>${escapeHtml(formatCompact(row.entryCount || 0))}</span>
          <span>${escapeHtml(row.reliability || "unknown")}</span>
          <span>${escapeHtml(formatEpochDate(row.dateUpdated || row.dateModified))}</span>
        </div>
      `
    )
    .join("");
  elements.blocklistTable.innerHTML = `
    <div class="blocklist-row blocklist-head">
      <span>Source</span><span>State</span><span>Entries</span><span>Reliability</span><span>Updated</span>
    </div>
    ${rows}
  `;
}

async function lookupProtectionDomain() {
  const domain = elements.protectionLookupInput?.value.trim() || "";
  if (!domain) {
    showStatus("Enter a domain to look up", "bad");
    return;
  }
  if (elements.protectionLookupResult) {
    elements.protectionLookupResult.innerHTML = '<div class="empty">Checking Pi-hole gravity…</div>';
  }
  try {
    const payload = await postJson("/api/protection/lookup", { domain });
    renderProtectionLookup(payload.lookup || {});
  } catch (error) {
    if (elements.protectionLookupResult) {
      elements.protectionLookupResult.innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
    }
  }
}

function renderProtectionLookup(lookup) {
  if (!elements.protectionLookupResult) {
    return;
  }
  const gravity = lookup.gravityMatches || [];
  const rules = lookup.domainRules || [];
  if (!gravity.length && !rules.length) {
    elements.protectionLookupResult.innerHTML = `<div class="empty">${escapeHtml(
      lookup.domain || "Domain"
    )} is not an exact match in Pi-hole gravity or domain rules.</div>`;
    return;
  }
  const gravityRows = gravity
    .map(
      (row) =>
        `<li>${escapeHtml(row.domain || lookup.domain)}${row.source ? ` · ${escapeHtml(blocklistName(row.source))}` : ""}</li>`
    )
    .join("");
  const ruleRows = rules
    .map((row) => `<li>${escapeHtml(row.domain)} · ${escapeHtml(domainRuleType(row.type))}</li>`)
    .join("");
  elements.protectionLookupResult.innerHTML = `
    <div class="lookup-card">
      <strong>${escapeHtml(lookup.domain || "Domain")}</strong>
      <p class="device-card-meta">Exact-match lookup. This does not inspect encrypted HTTPS page content.</p>
      ${gravityRows ? `<p class="field-label">Gravity matches</p><ul>${gravityRows}</ul>` : ""}
      ${ruleRows ? `<p class="field-label">Manual rules</p><ul>${ruleRows}</ul>` : ""}
    </div>
  `;
}

async function loadReport() {
  if (!elements.reportsPanel) return;
  const period = elements.reportPeriod?.value || "daily";
  const privacy = elements.reportPrivacy?.value || "family";
  try {
    const payload = await getJson(`/api/reports?period=${encodeURIComponent(period)}&privacy_level=${encodeURIComponent(privacy)}`);
    state.report = payload.report || null;
    renderReport();
  } catch (error) {
    if (elements.reportSummary) elements.reportSummary.innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
  }
}

function renderReport() {
  const report = state.report || {};
  const sections = report.sections || {};
  const dns = sections.dns || {};
  if (elements.reportSummary) {
    elements.reportSummary.innerHTML = [
      metricCard("Queries", formatCompact(dns.queries || 0)),
      metricCard("Blocked", formatCompact(dns.blocked || 0)),
      metricCard("Blocked %", `${dns.blockedPercent || 0}%`),
      metricCard("Devices", formatNumber(dns.activeDevices || 0)),
      metricCard("Domains", formatCompact(dns.domains || 0)),
      metricCard("Privacy", report.privacyLevel || "family"),
    ].join("");
  }
  renderRankList(elements.reportServices, sections.services || [], (row) => row.name, (row) => formatCompact(row.count || 0));
  renderRankList(elements.reportCategories, sections.categories || [], (row) => row.name, (row) => formatCompact(row.count || 0));
  renderRankList(elements.reportDomains, sections.domains || [], (row) => row.domain, (row) => formatCompact(row.count || 0));
  renderRankList(elements.reportAlerts, sections.alerts || [], (row) => row.title || row.alert_type, (row) => row.severity || "");
}

function exportReportCsv() {
  const period = elements.reportPeriod?.value || "daily";
  const privacy = elements.reportPrivacy?.value || "family";
  window.location.href = `/api/reports/export.csv?period=${encodeURIComponent(period)}&privacy_level=${encodeURIComponent(privacy)}`;
}

async function loadSystemHealth() {
  if (!elements.systemPanel) return;
  try {
    const payload = await getJson("/api/system/health");
    state.systemHealth = payload.health || null;
    renderSystemHealth();
  } catch (error) {
    if (elements.systemSummary) elements.systemSummary.innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
  }
}

async function applyEmergencyDnsOnly() {
  const confirmed = window.confirm(
    "Emergency DNS-only will stop ARP control, clear linked enrollments, and flush Pi-Circle network rules. Continue?"
  );
  if (!confirmed) return;
  try {
    const payload = await postJson("/api/network/emergency-dns-only");
    showStatus(`Emergency DNS-only applied. Cleared ${payload.clearedEnrollments || 0} enrollment(s).`, "good");
    await refresh();
    await loadSystemHealth();
  } catch (error) {
    showStatus(error.message, "bad");
  }
}

function renderSystemHealth() {
  const health = state.systemHealth || {};
  const resources = health.resources || {};
  const checks = health.checks || {};
  if (elements.systemSummary) {
    const services = health.services || [];
    const active = services.filter((service) => service.active).length;
    elements.systemSummary.innerHTML = [
      metricCard("Services", `${active}/${services.length || 0}`),
      metricCard("DNS test", checks.dnsResolution?.ok ? "OK" : "Fail"),
      metricCard("Internet", checks.internetReachability?.ok ? "OK" : "Fail"),
      metricCard("CPU load", resources.cpuLoad?.one ?? "—"),
      metricCard("Memory", `${resources.memory?.usedPercent ?? 0}%`),
      metricCard("Disk", `${resources.disk?.usedPercent ?? 0}%`),
    ].join("");
  }
  renderHealthRows(elements.systemServices, health.services || [], (row) => row.unit, (row) => row.state, (row) => row.active);
  if (elements.systemResources) {
    elements.systemResources.innerHTML = `
      <div><span class="field-label">Temperature</span><strong>${escapeHtml(resources.temperatureC == null ? "—" : `${resources.temperatureC}°C`)}</strong></div>
      <div><span class="field-label">Uptime</span><strong>${escapeHtml(formatDuration(resources.uptimeSeconds || 0))}</strong></div>
      <div><span class="field-label">Database</span><strong>${escapeHtml(formatBytes(resources.databaseBytes || 0))}</strong></div>
      <div><span class="field-label">Logs</span><strong>${escapeHtml(formatBytes(resources.logBytes || 0))}</strong></div>
      <div><span class="field-label">Gateway mode</span><strong>${escapeHtml(checks.gatewayIntegration?.mode || "—")}</strong></div>
      <div><span class="field-label">Linked targets</span><strong>${escapeHtml(String(checks.gatewayIntegration?.targetCount ?? 0))}</strong></div>
    `;
  }
  const actions = Object.entries(health.actions || {}).map(([name, detail]) => ({
    name,
    detail,
    active: !String(detail).startsWith("unavailable"),
  }));
  renderHealthRows(elements.systemActions, actions, (row) => row.name, (row) => row.detail, (row) => row.active);
}

async function loadSettingsPanels() {
  if (!elements.settingsPanel) return;
  try {
    const [capabilities, community, retention, security, audit, networkSettings] = await Promise.all([
      getJson("/api/setup/capabilities"),
      getJson("/api/community"),
      getJson("/api/retention"),
      getJson("/api/security/status"),
      getJson("/api/audit?limit=20"),
      getJson("/api/network/settings"),
    ]);
    state.capabilities = capabilities;
    state.community = community;
    state.retention = retention;
    state.security = security.security || null;
    state.auditEvents = audit.events || [];
    state.networkSettings = networkSettings;
    renderSettingsPanels();
  } catch (error) {
    if (elements.capabilityList) elements.capabilityList.innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
  }
}

function renderSettingsPanels() {
  renderHealthRows(
    elements.capabilityList,
    state.capabilities?.capabilities || [],
    (row) => row.label,
    (row) => `${row.status} · ${row.detail}`,
    (row) => row.enabled
  );
  renderNetworkSettingsPanel();
  renderCommunityPanel();
  renderRetentionPanel();
  const security = state.security || {};
  renderHealthRows(
    elements.securityStatus,
    [
      { name: "LAN admin gate", detail: security.lanAdminRequired ? "Enabled" : "Disabled", active: security.lanAdminRequired },
      { name: "Session window", detail: `${security.sessionMinutes || 0} minutes`, active: true },
      { name: "Audit retention", detail: `${security.auditRetentionDays || 0} days`, active: true },
      { name: "Webhook", detail: security.webhookConfigured ? "Configured" : "Not configured", active: Boolean(security.webhookConfigured) },
      ...(security.knownGaps || []).map((gap) => ({ name: "Known gap", detail: gap, active: false })),
    ],
    (row) => row.name,
    (row) => row.detail,
    (row) => row.active
  );
  renderHealthRows(
    elements.auditList,
    state.auditEvents,
    (row) => row.event_type || "event",
    (row) => `${row.result || "unknown"} · ${row.reason || ""}`,
    (row) => row.result === "success"
  );
}

function renderNetworkSettingsPanel() {
  if (!elements.networkSettingsPanel) return;
  const settings = state.networkSettings?.settings || { forceIpv4: true, forcePiDns: true };
  const linked = settings.linkedTargets || [];
  const forceIpv4 = settings.forceIpv4 !== false;
  const forcePiDns = settings.forcePiDns !== false;
  elements.networkSettingsPanel.innerHTML = `
    <label class="force-ipv4-toggle">
      <input type="checkbox" id="force-pi-dns-toggle" ${forcePiDns ? "checked" : ""} />
      <span>Force Pi DNS</span>
    </label>
    <p class="device-card-meta">${escapeHtml(state.networkSettings?.detail || "Hijacks DNS to Pi-hole for linked devices — no phone setup.")}</p>
    <label class="force-ipv4-toggle">
      <input type="checkbox" id="force-ipv4-toggle" ${forceIpv4 ? "checked" : ""} />
      <span>Force IPv4</span>
    </label>
    <p class="device-card-meta">Suppresses AAAA answers and drops forwarded IPv6.</p>
    <p class="device-card-meta">Linked now: ${linked.length ? escapeHtml(linked.join(", ")) : "none"} · mode ${escapeHtml(settings.mode || "—")}</p>
    <button class="secondary-button compact" type="button" id="network-settings-save">Save</button>
  `;
  elements.networkSettingsPanel.querySelector("#network-settings-save")?.addEventListener("click", saveNetworkSettings);
}

async function saveNetworkSettings() {
  const forceIpv4 = Boolean(elements.networkSettingsPanel?.querySelector("#force-ipv4-toggle")?.checked);
  const forcePiDns = Boolean(elements.networkSettingsPanel?.querySelector("#force-pi-dns-toggle")?.checked);
  try {
    state.networkSettings = await patchJson("/api/network/settings", {
      force_ipv4: forceIpv4,
      force_pi_dns: forcePiDns,
    });
    renderNetworkSettingsPanel();
    showStatus("Network settings saved", "good");
  } catch (error) {
    showStatus(error.message, "bad");
  }
}

function renderCommunityPanel() {
  if (!elements.communityPanel) return;
  const settings = state.community?.settings || { mode: "private" };
  const preview = state.community?.preview || { neverShare: [], sharedFields: [] };
  elements.communityPanel.innerHTML = `
    <div class="community-controls">
      <label class="field-label">Privacy mode
        <select class="type-select" id="community-mode">
          <option value="private"${settings.mode === "private" ? " selected" : ""}>Private Mode</option>
          <option value="anonymous"${settings.mode === "anonymous" ? " selected" : ""}>Anonymous Community Mode</option>
          <option value="organization"${settings.mode === "organization" ? " selected" : ""}>Organization Mode</option>
        </select>
      </label>
      <label class="field-label">Organization
        <input class="name-input" id="community-org" maxlength="80" value="${escapeAttribute(settings.organizationName || "")}" />
      </label>
      <button class="secondary-button compact" type="button" id="community-save">Save</button>
    </div>
    <p class="device-card-meta">Destination: ${escapeHtml(preview.destination || "none")}. Transport: ${escapeHtml(preview.transport || "not active")}.</p>
    <details class="advanced-details" open>
      <summary>Preview shared fields</summary>
      <ul class="profile-control-list">
        ${(preview.sharedFields || []).map((field) => `<li>${escapeHtml(field.field)} · ${escapeHtml(JSON.stringify(field.example))}</li>`).join("") || "<li>No fields shared in Private Mode.</li>"}
      </ul>
    </details>
    <details class="advanced-details">
      <summary>Never shared</summary>
      <ul class="profile-control-list">${(preview.neverShare || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
    </details>
  `;
  elements.communityPanel.querySelector("#community-save")?.addEventListener("click", saveCommunitySettings);
}

function renderRetentionPanel() {
  if (!elements.retentionPanel) return;
  const payload = state.retention || {};
  const settings = payload.settings || {};
  const wouldPrune = payload.wouldPrune || {};
  elements.retentionPanel.innerHTML = `
    <div class="retention-grid">
      ${retentionInput("Detailed activity", "retention-detailed", settings.detailedActivityDays || 30)}
      ${retentionInput("Alerts", "retention-alerts", settings.alertDays || 180)}
      ${retentionInput("Health history", "retention-health", settings.healthHistoryDays || 30)}
      ${retentionInput("Audit log", "retention-audit", settings.auditLogDays || 180)}
      ${retentionInput("Reports", "retention-reports", settings.reportDays || 365)}
    </div>
    <p class="retention-note">Dry run: ${escapeHtml(formatNumber(wouldPrune.bandwidthSamples || 0))} bandwidth samples, ${escapeHtml(formatNumber(wouldPrune.deviceUsageRows || 0))} usage rows, and ${escapeHtml(formatNumber(wouldPrune.alerts || 0))} alerts are older than current local retention windows.</p>
    <p class="retention-note">${escapeHtml(payload.note || "Pi-hole query retention is managed by Pi-hole.")}</p>
    <button class="secondary-button compact" type="button" id="retention-save">Save retention</button>
  `;
  elements.retentionPanel.querySelector("#retention-save")?.addEventListener("click", saveRetentionSettings);
}

function retentionInput(label, id, value) {
  return `
    <label class="field-label" for="${escapeAttribute(id)}">${escapeHtml(label)}
      <input class="name-input" id="${escapeAttribute(id)}" type="number" min="1" max="3650" step="1" value="${escapeAttribute(value)}" />
    </label>
  `;
}

async function saveRetentionSettings() {
  if (!elements.retentionPanel) return;
  const numberValue = (selector) => Number(elements.retentionPanel.querySelector(selector)?.value || 0);
  try {
    state.retention = await patchJson("/api/retention", {
      detailed_activity_days: numberValue("#retention-detailed"),
      alert_days: numberValue("#retention-alerts"),
      health_history_days: numberValue("#retention-health"),
      audit_log_days: numberValue("#retention-audit"),
      report_days: numberValue("#retention-reports"),
    });
    renderRetentionPanel();
    showStatus("Retention settings saved", "good");
  } catch (error) {
    showStatus(error.message, "bad");
  }
}

async function saveCommunitySettings() {
  const mode = elements.communityPanel?.querySelector("#community-mode")?.value || "private";
  const organizationName = elements.communityPanel?.querySelector("#community-org")?.value || "";
  try {
    state.community = await patchJson("/api/community", { mode, organization_name: organizationName });
    renderCommunityPanel();
    showStatus("Community privacy mode saved", "good");
  } catch (error) {
    showStatus(error.message, "bad");
  }
}

function renderHealthRows(container, rows, labelFn, detailFn, okFn) {
  if (!container) return;
  if (!rows.length) {
    container.innerHTML = '<div class="empty">No data yet.</div>';
    return;
  }
  container.innerHTML = rows
    .map((row) => {
      const ok = Boolean(okFn(row));
      return `
        <div class="health-row">
          <span class="state ${ok ? "good" : "warn"}">${ok ? "OK" : "Check"}</span>
          <div><strong>${escapeHtml(labelFn(row))}</strong><p class="device-card-meta">${escapeHtml(detailFn(row))}</p></div>
        </div>
      `;
    })
    .join("");
}

function initTheme() {
  let theme = "lcars";
  try {
    theme = localStorage.getItem("pi-circle-theme") || "lcars";
  } catch (_err) {
    theme = "lcars";
  }
  setTheme(theme, false);
}

function setTheme(theme, persist = true) {
  const next = theme === "stitch" ? "stitch" : "lcars";
  state.theme = next;
  document.documentElement.setAttribute("data-theme", next);
  elements.themeButtons.forEach((button) => {
    button.classList.toggle("active", button.dataset.themeSet === next);
  });
  if (persist) {
    try {
      localStorage.setItem("pi-circle-theme", next);
    } catch (_err) {
      /* ignore */
    }
  }
}

function initUiMode() {
  let mode = "simple";
  try {
    mode = localStorage.getItem("pi-circle-ui-mode") || "simple";
  } catch (_err) {
    mode = "simple";
  }
  setUiMode(mode, false);
}

function setUiMode(mode, persist = true) {
  const next = mode === "advanced" ? "advanced" : "simple";
  state.uiMode = next;
  document.documentElement.setAttribute("data-mode", next);
  if (elements.modeToggle) {
    elements.modeToggle.textContent = next === "advanced" ? "Advanced" : "Simple";
    elements.modeToggle.setAttribute("aria-pressed", String(next === "advanced"));
  }
  if (persist) {
    try {
      localStorage.setItem("pi-circle-ui-mode", next);
    } catch (_err) {
      /* ignore */
    }
  }
}

async function loadPiholeStatus() {
  try {
    const status = await getJson("/api/pihole/status");
    state.piholeStatus = status;
    if (state.pihole) {
      state.pihole.blocking_enabled = status.blocking_enabled;
      state.pihole.ftl_listening = status.ftl_listening;
      state.pihole.installed = status.installed;
      state.pihole.gravity_update = status.gravity_update || status.gravityUpdate || {};
    }
    renderPiholeStatus();
  } catch (error) {
    appendPiholeConsole(`Status error: ${error.message}`);
  }
}

function renderPiholeStatus() {
  const status = state.piholeStatus || {};
  const pihole = state.pihole || {};
  const blocking =
    status.blocking_enabled === true || pihole.blocking_enabled === true
      ? "Enabled"
      : status.blocking_enabled === false || pihole.blocking_enabled === false
        ? "Disabled"
        : "Unknown";
  const listening =
    status.ftl_listening === true || pihole.ftl_listening === true
      ? "Listening"
      : status.ftl_listening === false || pihole.ftl_listening === false
        ? "Down"
        : "—";
  if (elements.piholeStatusStrip) {
    elements.piholeStatusStrip.innerHTML = [
      metricCard("Blocking", blocking),
      metricCard("FTL", listening),
      metricCard("Adlists", formatNumber(pihole.enabled_adlists || 0)),
      metricCard("Gravity", formatCompact(pihole.gravity_domains || 0)),
      metricCard("Auto update", formatGravityUpdateSummary(status.gravity_update || pihole.gravity_update)),
    ].join("");
  }
  if (elements.piholeBlockingLabel) {
    elements.piholeBlockingLabel.textContent = `Pi-hole DNS filtering is ${blocking.toLowerCase()}. Blocklists update ${formatGravityUpdateSummary(
      status.gravity_update || pihole.gravity_update
    ).toLowerCase()}. Engine credit: Pi-hole.`;
  }
}

function appendPiholeConsole(message) {
  if (!elements.piholeConsole) return;
  const stamp = new Date().toLocaleTimeString();
  const line = `[${stamp}] ${message}`;
  const current = elements.piholeConsole.textContent.trim();
  elements.piholeConsole.textContent = current ? `${current}\n${line}` : line;
  elements.piholeConsole.scrollTop = elements.piholeConsole.scrollHeight;
}

async function runPiholeAction(action) {
  if (state.busy) return;
  state.busy = true;
  try {
    let path = "";
    let body = {};
    if (action === "enable") path = "/api/pihole/enable";
    if (action === "disable") path = "/api/pihole/disable";
    if (action === "disable-temp") {
      path = "/api/pihole/disable";
      body = { duration: elements.piholeDisableDuration?.value || "" };
    }
    if (action === "gravity") {
      path = "/api/pihole/gravity";
      body = { force: false };
    }
    if (action === "reload") path = "/api/pihole/reload";
    if (action === "flush") path = "/api/pihole/flush";
    showStatus(`Running Pi-hole ${action}…`, "info");
    const payload = await postJson(path, body);
    appendPiholeConsole(payload.result?.stdout || payload.result?.stderr || `${action} ok`);
    if (payload.status) state.piholeStatus = payload.status;
    await refresh();
    await loadPiholeStatus();
    showStatus(`Pi-hole ${action} complete`, "good");
  } catch (error) {
    appendPiholeConsole(`Error: ${error.message}`);
    showStatus(error.message, "bad");
  } finally {
    state.busy = false;
  }
}

async function runPiholeDomain(kind, action) {
  if (state.busy) return;
  const domain = (elements.piholeDomainInput?.value || "").trim();
  if (!domain) {
    showStatus("Enter a domain first", "bad");
    return;
  }
  state.busy = true;
  try {
    const path = kind === "allow" ? "/api/pihole/allow" : "/api/pihole/deny";
    const payload = await postJson(path, { domain, action });
    appendPiholeConsole(payload.result?.stdout || `${kind} ${action}: ${domain}`);
    elements.piholeDomainInput.value = "";
    await refresh();
    showStatus(`Updated ${kind}list for ${domain}`, "good");
  } catch (error) {
    appendPiholeConsole(`Error: ${error.message}`);
    showStatus(error.message, "bad");
  } finally {
    state.busy = false;
  }
}

function syncRouteFromHash() {
  const hash = window.location.hash.replace(/^#/, "");
  if (hash.startsWith("device/")) {
    openDevicePage(decodeURIComponent(hash.slice("device/".length)));
    return;
  }
  if (hash.startsWith("alert/")) {
    const alertId = Number(decodeURIComponent(hash.slice("alert/".length)));
    if (Number.isFinite(alertId)) {
      loadAlerts().then(() => openAlertReport(alertId));
      return;
    }
  }
  if (hash === "activity") {
    activateTab("activity");
    return;
  }
  if (hash === "overview") {
    activateTab("overview");
    return;
  }
  if (hash === "home" || hash === "devices") {
    activateTab("home");
    return;
  }
  if (hash === "services") {
    activateTab("services");
    return;
  }
  if (hash === "dns") {
    activateTab("dns");
    return;
  }
  if (hash === "pihole") {
    activateTab("pihole");
    return;
  }
  if (hash === "alerts") {
    activateTab("alerts");
    return;
  }
  if (hash === "controls") {
    activateTab("controls");
    return;
  }
  if (hash === "reports") {
    activateTab("reports");
    return;
  }
  if (hash === "system") {
    activateTab("system");
    return;
  }
  if (hash === "settings") {
    activateTab("settings");
    return;
  }
  activateTab("overview");
}

function showStatus(message, tone) {
  elements.statusMessage.textContent = message;
  elements.statusMessage.className = `status-message ${tone}`;
}

function isTargeted(device) {
  return new Set(state.config?.transparentControl?.targets ?? []).has(device.ip_address);
}

function isEnrolled(device) {
  return Boolean(device.transparent_control || device.managed);
}

function isGateway(device) {
  return device.ip_address === state.health?.gatewayIp;
}

function deviceCapabilityLabel(device) {
  if (isGateway(device)) {
    return "Gateway: not targetable";
  }
  if (isEnrolled(device) || isTargeted(device)) {
    return "Linked: internet pause + bandwidth available";
  }
  return "DNS-level protection only until linked";
}

function displayName(device) {
  return device.display_name || device.hostname || device.vendor || `Device ${device.ip_address.split(".").at(-1)}`;
}

function effectiveDeviceType(device) {
  if (isGateway(device)) {
    return "router";
  }
  return device.device_type || "unknown";
}

function typeLabel(type) {
  return DEVICE_TYPES.find(([value]) => value === type)?.[1] ?? "Device";
}

function serviceInitials(name) {
  const words = String(name || "?")
    .replaceAll("/", " ")
    .split(/\s+/)
    .filter(Boolean);
  return words.slice(0, 2).map((word) => word[0]?.toUpperCase() || "").join("") || "?";
}

function serviceConfidence(name) {
  const value = String(name || "").toLowerCase();
  if (!value || value === "example" || value === "unknown") {
    return "Unknown";
  }
  if (
    [
      "youtube",
      "tiktok",
      "instagram",
      "netflix",
      "discord",
      "whatsapp",
      "roblox",
      "steam",
      "playstation",
      "xbox",
      "apple",
      "google",
      "microsoft",
      "amazon",
    ].some((needle) => value.includes(needle))
  ) {
    return "Strong match";
  }
  return "Estimated";
}

function serviceCategoryLabel(name) {
  const value = String(name || "").toLowerCase();
  if (/youtube|netflix|video|twitch|disney|hulu|prime/.test(value)) return "Streaming";
  if (/tiktok|instagram|facebook|reddit|snap|twitter|x \/ twitter/.test(value)) return "Social media";
  if (/discord|whatsapp|telegram|signal|messenger|slack/.test(value)) return "Messaging";
  if (/roblox|steam|xbox|playstation|nintendo|minecraft|game/.test(value)) return "Gaming";
  if (/google|bing|duckduckgo|yahoo/.test(value)) return "Search";
  if (/apple|microsoft|amazon|cloudflare|akamai|fastly/.test(value)) return "Platform";
  return "Other";
}

function serviceDomainMatch(serviceName, domain) {
  const service = String(serviceName || "").toLowerCase().replace(/[^a-z0-9]+/g, "");
  const host = String(domain || "").toLowerCase().replace(/[^a-z0-9]+/g, "");
  if (!service || !host) {
    return false;
  }
  return host.includes(service.slice(0, Math.min(service.length, 8)));
}

function deviceIcon(type) {
  const icons = {
    router: '<svg viewBox="0 0 48 48" aria-hidden="true"><path d="M8 28h32v10H8z"/><path d="M15 28c3-5 15-5 18 0" fill="none"/><circle cx="16" cy="33" r="1.6"/><circle cx="22" cy="33" r="1.6"/><path d="M14 20c6-6 14-6 20 0M18 24c4-3 8-3 12 0" fill="none"/></svg>',
    iphone: '<svg viewBox="0 0 48 48" aria-hidden="true"><rect x="15" y="6" width="18" height="36" rx="4"/><circle cx="24" cy="37" r="1.4"/><path d="M21 10h6" fill="none"/></svg>',
    ipad: '<svg viewBox="0 0 48 48" aria-hidden="true"><rect x="12" y="5" width="24" height="38" rx="4"/><circle cx="24" cy="38" r="1.4"/></svg>',
    android: '<svg viewBox="0 0 48 48" aria-hidden="true"><rect x="12" y="16" width="24" height="22" rx="4"/><path d="M17 16l-3-5M31 16l3-5M18 24h.1M30 24h.1" fill="none"/><path d="M9 21v11M39 21v11" fill="none"/></svg>',
    pc: '<svg viewBox="0 0 48 48" aria-hidden="true"><rect x="7" y="9" width="34" height="23" rx="2"/><path d="M18 39h12M24 32v7" fill="none"/></svg>',
    laptop: '<svg viewBox="0 0 48 48" aria-hidden="true"><rect x="10" y="10" width="28" height="20" rx="2"/><path d="M6 37h36l-4-7H10z"/></svg>',
    tv: '<svg viewBox="0 0 48 48" aria-hidden="true"><rect x="7" y="10" width="34" height="24" rx="3"/><path d="M18 40h12M24 34v6" fill="none"/></svg>',
    game: '<svg viewBox="0 0 48 48" aria-hidden="true"><path d="M14 20h20c4 0 7 4 8 12 .4 3-3 5-5 3l-5-5H16l-5 5c-2 2-5 0-5-3 1-8 4-12 8-12z"/><path d="M16 27h8M20 23v8M32 26h.1M36 30h.1" fill="none"/></svg>',
    iot: '<svg viewBox="0 0 48 48" aria-hidden="true"><path d="M24 5a13 13 0 0 1 8 23v8H16v-8A13 13 0 0 1 24 5z"/><path d="M17 42h14M19 36h10" fill="none"/></svg>',
    unknown: '<svg viewBox="0 0 48 48" aria-hidden="true"><circle cx="24" cy="24" r="17"/><path d="M19 19a5 5 0 1 1 8 4c-2 1-3 2-3 5M24 35h.1" fill="none"/></svg>',
  };
  return icons[type] || icons.unknown;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function escapeAttribute(value) {
  return escapeHtml(value).replaceAll("`", "&#096;");
}

function formatNumber(value) {
  return new Intl.NumberFormat().format(value);
}

function formatCompact(value) {
  return new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(value);
}

function formatOptionalCompact(value) {
  if (value == null) {
    return "Deferred";
  }
  return formatCompact(value);
}

function formatBytes(value) {
  const amount = Number(value) || 0;
  if (amount < 1024) return `${amount} B`;
  if (amount < 1024 ** 2) return `${(amount / 1024).toFixed(1)} KB`;
  if (amount < 1024 ** 3) return `${(amount / 1024 ** 2).toFixed(1)} MB`;
  return `${(amount / 1024 ** 3).toFixed(2)} GB`;
}

function formatBytesPerSec(value) {
  return `${formatBytes(value)}/s`;
}

function formatDuration(seconds) {
  const value = Math.max(0, Number(seconds) || 0);
  const days = Math.floor(value / 86400);
  const hours = Math.floor((value % 86400) / 3600);
  const minutes = Math.floor((value % 3600) / 60);
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

function formatStardate(date) {
  const year = date.getUTCFullYear();
  const start = Date.UTC(year, 0, 1);
  const day = (date.getTime() - start) / 86400000;
  return `${year - 1900}${day.toFixed(1)}`;
}

function formatEventTime(timestamp) {
  if (!timestamp) {
    return "--:--:--";
  }
  return new Date(Number(timestamp) * 1000).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function formatIsoTime(value) {
  if (!value) {
    return "Unknown time";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }
  return date.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function formatEpochDate(value) {
  const seconds = Number(value || 0);
  if (!seconds) {
    return "—";
  }
  const date = new Date(seconds * 1000);
  if (Number.isNaN(date.getTime())) {
    return "—";
  }
  return date.toLocaleDateString([], { month: "short", day: "numeric" });
}

function blocklistName(address) {
  try {
    const url = new URL(address);
    return url.hostname.replace(/^www\./, "");
  } catch (_err) {
    return address || "Local list";
  }
}

function domainRuleType(type) {
  const value = Number(type);
  if (value === 0 || value === 2) return "Allow rule";
  if (value === 1) return "Block rule";
  if (value === 3) return "Regex block rule";
  return "Domain rule";
}

function formatAge(seconds) {
  if (seconds == null || Number.isNaN(Number(seconds))) {
    return "never";
  }
  const value = Math.max(0, Number(seconds));
  if (value < 5) return "just now";
  if (value < 60) return `${value}s ago`;
  if (value < 3600) return `${Math.floor(value / 60)}m ago`;
  return `${Math.floor(value / 3600)}h ago`;
}

function toTimeInput(value) {
  if (!value) {
    return "";
  }
  const match = String(value).match(/^(\d{1,2}):(\d{2})$/);
  if (!match) {
    return "";
  }
  return `${String(match[1]).padStart(2, "0")}:${match[2]}`;
}

function wait(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function startInventoryPolling() {
  if (state.inventoryTimer) {
    return;
  }
  state.inventoryTimer = window.setInterval(() => {
    if (state.activeTab === "home" && !state.selectedIp && !state.busy) {
      refreshInventory(false).catch(() => {});
    }
  }, 3000);
}

refresh().then(() => {
  syncRouteFromHash();
  startInventoryPolling();
});
setInterval(refresh, 12000);
setInterval(() => {
  loadAlerts();
}, 8000);
