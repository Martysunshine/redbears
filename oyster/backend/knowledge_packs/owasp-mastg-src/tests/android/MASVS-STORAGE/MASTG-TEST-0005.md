<!-- source: https://github.com/OWASP/mastg/blob/0e88142b5d7aad8f052b4e75199a8aad9b89d5b5/tests/android/MASVS-STORAGE/MASTG-TEST-0005.md -->
---
masvs_v1_id:
- MSTG-STORAGE-4
masvs_v2_id:
- MASVS-STORAGE-2
platform: android
title: Determining Whether Sensitive Data Is Shared with Third Parties via Notifications
masvs_v1_levels:
- L1
- L2
profiles: [L1, L2]
status: deprecated
covered_by: [MASTG-TEST-0315]
deprecation_note: New version available in MASTG V2
---

## Overview

## Static Analysis

Search for any usage of the `NotificationManager` class which might be an indication of some form of notification management. If the class is being used, the next step would be to understand how the application is [generating the notifications](https://developer.android.com/training/notify-user/build-notification#SimpleNotification "Create a Notification") and which data ends up being shown.

## Dynamic Analysis

Run the application and start tracing all calls to functions related to the notifications creation, e.g. `setContentTitle` or `setContentText` from [`NotificationCompat.Builder`](https://developer.android.com/reference/androidx/core/app/NotificationCompat.Builder). Observe the trace in the end and evaluate if it contains any sensitive information which another app might have eavesdropped.
