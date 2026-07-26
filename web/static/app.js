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
  setupBanner: document.querySelector("#setup-banner"),
  deviceHistoryChart: document.querySelector("#device-history-chart"),
  historyWindowToggle: document.querySelector("#history-window-toggle"),
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
elements.historyWindowToggle?.querySelectorAll("[data-history-window]").forEach((button) => {
  button.addEventListener("click", () => {
    state.historyWindow = button.dataset.historyWindow || "24h";
    elements.historyWindowToggle.querySelectorAll("[data-history-window]").forEach((node) => {
      node.classList.toggle("active-window", node === button);
    });
    loadHistory();
  });
});
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
elements.themeButtons.forEach((button) => {
  button.addEventListener("click", () => setTheme(button.dataset.themeSet || "lcars"));
});
window.addEventListener("hashchange", () => syncRouteFromHash());
initTheme();

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
    if (state.activeTab === "alerts") {
      renderAlerts();
    }
    if (state.activeTab === "dns" || state.activeTab === "pihole") {
      renderDnsPanel();
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

async function ackAllAlerts() {
  await runAction("Alerts cleared", async () => {
    await postJson("/api/alerts/ack-all");
    await loadAlerts();
  });
}

async function ackAlert(alertId) {
  await postJson(`/api/alerts/${alertId}/ack`);
  await loadAlerts();
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
  renderDeviceInfo();
  renderAlertBadge();
  renderSetupBanner();
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
  state.devices.forEach((device) => {
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
      </div>
      <span class="state ${policy.blocked || device.paused ? "paused" : online ? (isTargeted(device) || isEnrolled(device) ? "linked" : "online") : "offline"}">
        <span class="presence-dot"></span>${escapeHtml(status)}
      </span>
    `;
    elements.deviceGrid.appendChild(card);
  });
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

function activateTab(target) {
  state.activeTab = target;
  elements.tabs.forEach((tab) => tab.classList.toggle("active", tab.dataset.tabTarget === target));
  stopActivityPolling();
  elements.homePanel?.classList.add("hidden");
  elements.activityPanel?.classList.add("hidden");
  elements.dnsPanel?.classList.add("hidden");
  elements.piholePanel?.classList.add("hidden");
  elements.alertsPanel?.classList.add("hidden");
  elements.controlsPanel?.classList.add("hidden");
  elements.devicePage?.classList.add("hidden");
  if (target === "home") {
    closeDevicePage(false);
    elements.homePanel?.classList.remove("hidden");
    history.replaceState(null, "", "#home");
  }
  if (target === "activity") {
    stopDevicePolling();
    state.selectedIp = null;
    elements.activityPanel?.classList.remove("hidden");
    history.replaceState(null, "", "#activity");
    loadHistory();
    reloadActivity(true);
    startActivityPolling();
  }
  if (target === "dns") {
    stopDevicePolling();
    state.selectedIp = null;
    elements.dnsPanel?.classList.remove("hidden");
    history.replaceState(null, "", "#dns");
    renderDnsPanel();
  }
  if (target === "pihole") {
    stopDevicePolling();
    state.selectedIp = null;
    elements.tabs.forEach((tab) => tab.classList.toggle("active", tab.dataset.tabTarget === "dns"));
    elements.piholePanel?.classList.remove("hidden");
    history.replaceState(null, "", "#pihole");
    renderDnsPanel();
    loadPiholeStatus();
  }
  if (target === "alerts") {
    stopDevicePolling();
    state.selectedIp = null;
    elements.alertsPanel?.classList.remove("hidden");
    history.replaceState(null, "", "#alerts");
    loadAlerts();
  }
  if (target === "controls") {
    stopDevicePolling();
    state.selectedIp = null;
    elements.controlsPanel?.classList.remove("hidden");
    history.replaceState(null, "", "#controls");
  }
}

function openDevicePage(ipAddress) {
  state.selectedIp = ipAddress;
  state.activeTab = "home";
  stopActivityPolling();
  elements.tabs.forEach((tab) => tab.classList.toggle("active", tab.dataset.tabTarget === "home"));
  elements.homePanel?.classList.add("hidden");
  elements.activityPanel?.classList.add("hidden");
  elements.dnsPanel?.classList.add("hidden");
  elements.alertsPanel?.classList.add("hidden");
  elements.controlsPanel?.classList.add("hidden");
  elements.devicePage?.classList.remove("hidden");
  history.replaceState(null, "", `#device/${ipAddress}`);
  loadDevicePage(ipAddress, true);
  startDevicePolling();
}

function closeDevicePage(updateHash = true) {
  stopDevicePolling();
  state.selectedIp = null;
  state.devicePage = null;
  elements.devicePage?.classList.add("hidden");
  elements.homePanel?.classList.remove("hidden");
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

function renderAlerts() {
  if (!elements.alertsList) {
    return;
  }
  if (!state.alerts.length) {
    elements.alertsList.innerHTML = '<div class="empty">No alerts. You’re clear.</div>';
    return;
  }
  elements.alertsList.innerHTML = "";
  state.alerts.forEach((alert) => {
    const row = document.createElement("article");
    row.className = `alert-card ${alert.severity || "info"} ${alert.acked ? "acked" : ""}`;
    row.innerHTML = `
      <div>
        <p class="alert-title">${escapeHtml(alert.title)}</p>
        <p class="device-card-meta">${escapeHtml(alert.detail || "")}</p>
        <p class="device-card-meta">${escapeHtml(alert.created_at || "")} · ${escapeHtml(alert.alert_type || "")}</p>
      </div>
      <div class="action-row">
        ${alert.subject ? `<button class="secondary-button compact" type="button" data-open="${escapeAttribute(alert.subject)}">Open</button>` : ""}
        ${alert.acked ? "" : `<button class="primary-button compact" type="button" data-ack="${alert.id}">Ack</button>`}
      </div>
    `;
    row.querySelector("[data-ack]")?.addEventListener("click", () => ackAlert(alert.id));
    row.querySelector("[data-open]")?.addEventListener("click", (event) => {
      openDevicePage(event.currentTarget.dataset.open);
    });
    elements.alertsList.appendChild(row);
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
  if (state.setup.ready && !dismissed) {
    // Show a compact healthy strip once per session.
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
      elements.deviceLiveFeed.innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
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
        "Pause/schedule is saved, but this device must be <strong>Linked</strong> for Pi-Circle to cut the internet.";
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
  const pad = 16;
  const maxRate = Math.max(1, ...series.map((row) => Number(row.bytesPerSec) || 0));
  const step = (width - pad * 2) / Math.max(1, series.length - 1);
  const points = series.map((row, index) => {
    const x = pad + index * step;
    const y = height - pad - ((Number(row.bytesPerSec) || 0) / maxRate) * (height - pad * 2);
    return `${x},${y}`;
  });
  const area = `${pad},${height - pad} ${points.join(" ")} ${pad + (series.length - 1) * step},${height - pad}`;
  container.innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" class="traffic-svg bandwidth-svg">
      <polygon fill="rgba(102,204,170,0.18)" points="${area}"></polygon>
      <polyline fill="none" stroke="#66ccaa" stroke-width="3" points="${points.join(" ")}"></polyline>
    </svg>
    <div class="chart-caption">Peak ${escapeHtml(formatBytesPerSec(maxRate))}</div>
  `;
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
        ${paused ? "Resume internet" : "Pause internet"}
      </button>
      <button class="${isEnrolled(device) || isTargeted(device) ? "secondary-button" : "primary-button"}" type="button" id="info-link">
        ${isGateway(device) ? "Router" : isEnrolled(device) || isTargeted(device) ? "Unlink" : "Link"}
      </button>
    </div>
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
  const pad = 16;
  const maxQueries = Math.max(1, ...series.map((row) => Number(row.queries) || 0));
  const step = (width - pad * 2) / Math.max(1, series.length - 1);
  const points = series.map((row, index) => {
    const x = pad + index * step;
    const y = height - pad - ((Number(row.queries) || 0) / maxQueries) * (height - pad * 2);
    return `${x},${y}`;
  });
  const blockedBars = series
    .map((row, index) => {
      const value = Number(row.blocked) || 0;
      if (!value) {
        return "";
      }
      const barHeight = (value / maxQueries) * (height - pad * 2);
      const x = pad + index * step - 2;
      const y = height - pad - barHeight;
      return `<rect x="${x}" y="${y}" width="4" height="${barHeight}" fill="#cc6666" opacity="0.85"></rect>`;
    })
    .join("");
  container.innerHTML = `
    <svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" class="traffic-svg">
      <polyline fill="none" stroke="#ff9900" stroke-width="3" points="${points.join(" ")}"></polyline>
      ${blockedBars}
    </svg>
  `;
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
      <div><span class="field-label">Mode</span><strong>${escapeHtml(health.mode || state.config?.mode || "—")}</strong></div>
    `;
  }
  renderPiholeStatus();
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

async function loadPiholeStatus() {
  try {
    const status = await getJson("/api/pihole/status");
    state.piholeStatus = status;
    if (state.pihole) {
      state.pihole.blocking_enabled = status.blocking_enabled;
      state.pihole.ftl_listening = status.ftl_listening;
      state.pihole.installed = status.installed;
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
    ].join("");
  }
  if (elements.piholeBlockingLabel) {
    elements.piholeBlockingLabel.textContent = `Pi-hole blocking is ${blocking.toLowerCase()}. Engine credit: Pi-hole.`;
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
    openDevicePage(hash.slice("device/".length));
    return;
  }
  if (hash === "activity") {
    activateTab("activity");
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
  activateTab("home");
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
