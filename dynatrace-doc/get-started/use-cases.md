# Use cases

With the ingested data, you can accomplish various use cases, such as

## Visualize and analyze security findings

Create dashboards that show the compliance posture of your Kubernetes clusters at a glance:

* **Compliance summary** — total compliant vs. non-compliant resources across all policies
* **Severity breakdown** — findings grouped by Critical, High, Medium, Low
* **Policy violation trends** — track how compliance changes over time after policy updates
* **Namespace-level compliance** — identify which namespaces have the most violations
* **Workload-level drill-down** — pinpoint which specific Deployments, StatefulSets, or DaemonSets are non-compliant

## Automate and orchestrate security findings

Build Dynatrace Workflows that trigger automatically when new non-compliant events are detected:

* **Alerting** — send notifications to Slack, PagerDuty, or email when critical policy violations are found
* **Ticket creation** — automatically create Jira or ServiceNow tickets for high-severity findings
* **Remediation** — trigger Kubernetes actions via workflow integrations
* **Compliance reporting** — generate periodic summary reports and distribute them to stakeholders

## Correlate with other security data

Because Kyverno findings are stored as Grail security events alongside other security data, you can:

* **Cross-reference** container image vulnerabilities with Kyverno image verification failures
* **Correlate** runtime security events with admission-time policy violations
* **Unified dashboards** combining Kyverno compliance data with vulnerability findings and runtime detections
