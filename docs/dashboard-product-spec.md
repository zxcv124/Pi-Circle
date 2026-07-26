# Dashboard Product Spec

## Product Experience

The dashboard should feel like a local network command center for parents or administrators, not a technical packet tool. The first screen should show the current home network state, which devices are protected, which devices need attention, and whether network control is healthy.

## Information Architecture

Primary navigation:

- Overview
- Devices
- Profiles
- Rules
- Activity
- Network
- Settings
- Audit

## Overview

Components:

- 3D network map with router, Pi-Circle appliance, and devices arranged by profile or activity.
- Health strip for DNS, Pi-hole, routing, gateway, internet, storage, and backups.
- Active controls summary for paused devices, bedtime policies, and recently blocked categories.
- Recent audit events.

## 3D Device Map

Implementation:

- Use Three.js for the 3D scene.
- Render router and Pi appliance as fixed anchors.
- Render devices as accessible, selectable nodes with iconography by device class.
- Use color and motion sparingly to indicate state: protected, paused, warning, offline, unmanaged.
- Provide a 2D accessible list equivalent for screen readers and reduced-motion users.

Interactions:

- Select device node to open detail panel.
- Filter by profile, state, and device type.
- Toggle layout between topology, family profile, and activity intensity.
- Provide hover tooltips and keyboard focus states.

Performance:

- Maintain stable frame rate on Raspberry Pi hardware.
- Use bounded node count and level-of-detail rendering for large networks.
- Avoid heavy shaders and excessive animation.

## Device Detail

Fields:

- Device name.
- Owner/profile.
- MAC address with privacy-conscious display.
- IP address.
- Hostname.
- Identity confidence.
- Last seen.
- DNS policy.
- Transparent control state.
- Recent blocked requests.
- Recent routed traffic summary.

Actions:

- Assign profile.
- Pause internet.
- Resume internet.
- Set bedtime.
- Add allow rule.
- Add deny rule.
- Mark as unmanaged.
- Forget device.

## Profiles

Profile settings:

- Name.
- Devices.
- Age band or policy template.
- Bedtime schedule.
- Daily time budget.
- Allowed categories.
- Blocked categories.
- Search safety.
- YouTube or streaming restrictions where enforceable through DNS/categories.
- Override PIN workflow.

## Network Health

Checks:

- Pi-hole API reachable.
- FTL running.
- DNS queries succeeding.
- Gateway reachable.
- Internet reachable through configured path.
- `nftables` rules match expected state.
- Transparent-control clients have valid routes.
- IPv6 bypass status.
- Disk space and database health.

## Settings

Sections:

- Admin account.
- Local access restrictions.
- Deployment mode.
- Device discovery.
- Pi-hole integration.
- Backup and restore.
- Updates.
- Logs and privacy.
- Emergency disable.

## Accessibility

Requirements:

- WCAG AA color contrast.
- Full keyboard operation.
- Reduced motion support.
- Screen-reader equivalent for 3D map.
- Visible focus indicators.
- No information conveyed by color alone.

## Visual System

Use restrained, premium SaaS styling:

- Neutral foundation with clear semantic colors.
- 8px or smaller card radius unless inherited design system differs.
- Dense but readable operational layout.
- Light and dark themes.
- Consistent icon set.
- Skeletons for loading states.
- Inline validation and recoverable error states.

## Analytics Events

Capture local product analytics without sending personal data externally by default:

- Dashboard viewed.
- Device assigned to profile.
- Policy changed.
- Pause/resume used.
- Transparent mode enabled/disabled.
- Health warning shown.
- Rollback triggered.

If cloud administration is added later, analytics must be opt-in and documented.
