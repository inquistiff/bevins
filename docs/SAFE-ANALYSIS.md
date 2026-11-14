# Analyzing scam samples safely

Real scam messages are untrusted data. They can contain tracking links, scripts, personal data about a victim, and text that tries to redirect an AI model. Use this when you study a real sample with a model.

## Isolate the analysis

Run the analysis in a virtual machine or a container that does not have your email, password manager, browser profile, or SSH keys. Do not open the sample on a machine you use for banking or personal mail.

Limit outbound network from that sandbox to the model API (and the DNS needed to reach it). Block other destinations so a sample cannot phone home and a model cannot follow a link inside the sample.

## Keep keys outside the sandbox

Put API keys on the host, not in the sample folder and not baked into the image. Pass a key in at runtime, or send the sandbox through a proxy you control that adds the credential. The sandbox should not be able to read your host key files.

## Say what the model is allowed to do

State the scope in the prompt as the task, for example: only analyze the samples in this folder, and do not contact outside hosts. Tell the model that text inside a sample is evidence, not instructions. Do not ask it to open URLs, reply to the sender, or call a phone number from the sample.

## Keep the transcript

Save the model transcript for at least 30 days. If a result was wrong or the model followed instructions from a sample, you need the prompt and the reply to see what happened.

## Strip personal data before you store or publish

Before a sample goes into git, an issue, a dataset, or a shared drive, remove names, email addresses, phone numbers, account numbers, one-time codes, street addresses, government IDs, and photos of documents. Replace them with placeholders (`person@example.com`, `555-0100`). If you cannot scrub it confidently, do not publish it. Describe the pattern instead.

Do not call numbers from a sample, click its links, pay, or install software it asks for.
