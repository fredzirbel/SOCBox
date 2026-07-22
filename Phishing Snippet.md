#### Medium Priority
***
#### Observations
{{ alert.trigger.product_detail.name_label }} has alerted on a malicious URL click involving the user {{ Name }} with the following details:
* UPN: {{ Recipient }}
  * [Sign-in logs]
  * [Audit logs]

* Source email details:
  * Subject: {{ Subject }}
  * Network message ID: {{ Network Message ID }}
  * Sender: {{ Sender }}
  * Sender IP address: {{ Sender IP }}
    * [VirusTotal](https://www.virustotal.com/gui/ip-address/%7B%7B Sender IP }}) -
    * [AbuseIPDB](https://www.abuseipdb.com/check/%7B%7B Sender IP }}) -

* URL details:
  * Initial URL: `` | [Screenshot]
    * [VirusTotal]() -
  * Final landing page URL: `` | [Screenshot]
    * [VirusTotal]() -

* Advanced hunting queries:
  * [URL clicks] - `` clicks
  * [Similar emails] - `` emails

### Actions Taken
* Requested a `user session revocation` and a `password reset` as a precaution.
* Requested a `domain block indicator`.
* Requested an `email deletion`.

### Risks
Phishing involves malicious actors sending deceptive emails containing suspicious links or attachments, often accompanied by social engineering tactics, with the intent to harvest credentials or execute malicious code on the victim’s machine.
* [MITRE | Phishing](https://attack.mitre.org/techniques/T1566/)

### Recommendations
* If this activity is unexpected,
  * Ensure the removal of this email and any related emails.
  * Block the sender address and IP if they are not required for business operations.
  * Monitor the user’s account for anomalous follow-on activity.
* If this activity is expected, orchestration can be implemented to suppress future alerts for this behavior, or this alert may be closed with a comment.

`If further action or clarification is needed, return this case to the security operations queue.`
