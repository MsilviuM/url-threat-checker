# Simple Project Description: Link Safety Checker

## What We Are Building

We are building a small system that helps people check if links they receive are safe or dangerous.

The idea is simple:

Someone receives a message, email, or chat that contains a link. Our system takes that link, checks it using our own program, asks VirusTotal for a second opinion, and then shows the user a clear result.

Example:

```text
Someone receives this link:
http://fake-bank-login-example.com/verify

Our system checks it and says:
Warning: this link looks dangerous. Do not open it.
```

The final project should feel like a simple cybersecurity assistant.

It will not be perfect like a real antivirus product, and that is okay. The goal is to show that we understand how to combine programming, machine learning, APIs, and automation into one useful project.

## The Main Problem

People often receive suspicious links through:

- Email
- Telegram
- Slack
- WhatsApp
- Other chat apps

Some of these links are safe.

Some are dangerous and can lead to:

- Fake login pages
- Phishing attacks
- Malware downloads
- Scam websites

Our project tries to detect these dangerous links before the user opens them.

## The Simple Version Of The Idea

The system works like this:

```text
1. A message arrives with a link.
2. Our system finds the link inside the message.
3. Our own checker analyzes the link.
4. VirusTotal is used as a second opinion.
5. The system decides if the link is safe, suspicious, or dangerous.
6. The user gets a warning and can open a full report on our website.
```

That is the whole idea.

Everything else is just building this step by step.

## Important Words Explained Simply

### URL

A URL is just a web link.

Example:

```text
https://google.com
```

or:

```text
http://fake-login-bank-example.com/account
```

### Phishing

Phishing is when someone creates a fake website that tries to trick people.

Example:

A fake website may look like a bank login page and ask the user to enter their password.

### Malware

Malware is dangerous software.

A bad link may download malware or send the user to a page that tries to infect their device.

### Machine Learning

Machine learning means we give the computer many examples and let it learn patterns from them.

For this project, we give it many links that are already labeled as:

- Safe
- Phishing
- Malware
- Defacement

Then the program learns what dangerous links usually look like.

### VirusTotal

VirusTotal is a website/API that checks links using many security engines.

We use it as a second opinion.

Important: VirusTotal is not always 100% correct, but it is a very useful external reference.

### Webhook

A webhook is just a way for another app to send information to our app automatically.

Simple example:

```text
Telegram receives a message
Telegram sends that message to our server
Our server checks if the message contains links
```

So a webhook is like an automatic notification.

## The Main Parts Of The Project

We can think about the project as 6 small blocks.

### Block 1: Message Receiver

This part receives messages from outside platforms.

For example:

- Telegram bot receives a message
- Email inbox receives an email
- Slack channel receives a message

In the first version, we do not need to support everything.

We can start with one easy source, like Telegram, then add email or Slack later.

### Block 2: Link Extractor

This part looks inside the message and finds links.

Example message:

```text
Hello, please check this link: http://example.com/login
```

The link extractor finds:

```text
http://example.com/login
```

If a message has more than one link, it can extract all of them.

### Block 3: Our Own Link Checker

This is the part we build ourselves.

It looks at the link and extracts simple information from it.

For example:

- How long is the link?
- Does it use HTTPS?
- Does it contain words like login, verify, account, password?
- Does the domain have many dots?
- Does it contain many numbers?
- Is the domain on a trusted list?

Then the machine learning model uses this information to make a prediction.

Example result:

```text
Prediction: phishing
Confidence: 87%
```

This means our model thinks the link looks like phishing.

### Block 4: VirusTotal Checker

After our own checker gives a result, we can also ask VirusTotal.

VirusTotal gives information like:

```text
8 security engines marked this link as malicious
2 marked it as suspicious
60 marked it as harmless
```

This helps us compare our own result with an external security tool.

### Block 5: Final Decision

This part combines the results.

It looks at:

- What our model predicted
- How confident our model was
- What VirusTotal said
- Whether the domain is trusted
- Whether the link has suspicious signs

Then it gives a final verdict:

```text
Safe
Suspicious
Dangerous
```

Example:

```text
Final verdict: Dangerous
Reason: Our model classified it as phishing, and VirusTotal also found malicious detections.
```

### Block 6: Website With Reports

The website shows the user what happened.

It should have:

- A dashboard
- A list of scanned links
- A full report page for each link

Example report page:

```text
URL: hxxp://fake-bank-login[.]com
Final verdict: Dangerous
Our model: Phishing, 91% confidence
VirusTotal: 9 malicious detections
Recommendation: Do not open this link.
```

We should avoid showing dangerous links as clickable links. Instead, we can write them safely like this:

```text
hxxp://fake-site[.]com
```

This is called defanging a URL.

## What The User Will See

The user receives a warning like:

```text
Warning: a suspicious link was detected.

Link:
hxxp://fake-bank-login[.]com

Verdict:
Dangerous

Reason:
The link looks like phishing and VirusTotal also detected problems.

Full report:
http://our-website.com/reports/123
```

The user does not need to understand the technical details.

They only need to know:

```text
Is this link safe or not?
Why?
What should I do?
```

## What We Should Build First

We should not try to build everything at once.

The easiest first version is:

```text
1. A simple page where the user pastes a link.
2. Our program analyzes the link.
3. The program shows safe, suspicious, or dangerous.
4. The result is saved in a small database.
5. The user can open a report page.
```

After that works, we add:

```text
6. VirusTotal comparison.
7. Telegram message integration.
8. Email or Slack integration.
9. A nicer dashboard.
```

This way the project grows slowly and safely.

## The Recommended First Demo

The first good demo could be:

```text
1. We open the website.
2. We paste a suspicious link.
3. The system analyzes it.
4. It shows the result.
5. We open the full report.
6. Then we send a message to a Telegram bot.
7. The bot detects the link and replies with a warning.
```

This is already impressive enough for a university project.

## Why This Project Is Good

This project is good because it combines several real programming topics:

- Web development
- APIs
- Machine learning
- Cybersecurity
- Databases
- Background processing
- User notifications

But each part can be built step by step.

We do not need to understand everything on day one.

## What Each Technology Does

### Python

Python will be used for the machine learning part.

It will:

- Load the dataset
- Extract features from URLs
- Train the model
- Predict if a new URL is safe or dangerous

### FastAPI

FastAPI can expose the Python checker as a small API.

Example:

```text
Our app sends a URL to FastAPI.
FastAPI returns the prediction.
```

### Database

The database stores:

- Messages
- Links
- Scan results
- Reports

### Website

The website lets users see:

- Dashboard
- Scanned links
- Full reports

### Telegram, Email, Or Slack

These are optional input sources.

They are useful because they make the project feel real.

Instead of only pasting a link manually, the system can receive links from real messages.

## What We Should Be Careful About

### We Should Not Say The System Is Perfect

No security system is perfect.

Better wording:

```text
The system helps detect suspicious links.
```

Avoid:

```text
The system detects all dangerous links perfectly.
```

### VirusTotal Is A Second Opinion

VirusTotal is useful, but it is not absolute truth.

Better wording:

```text
VirusTotal is used as an external reference.
```

Avoid:

```text
VirusTotal gives the 100% correct answer.
```

### Do Not Open Dangerous Links

Our system should analyze the link text.

It should not open suspicious websites directly in a browser.

This keeps the demo safer.

## Simple Final Description For The Project

This is the simple explanation:

```text
We are building a system that checks links from messages and emails.

When a link is received, the system analyzes it using our own machine learning model. The model looks at simple signs, such as the length of the link, suspicious words, HTTPS usage, numbers, and domain structure.

Then the system compares the result with VirusTotal, which gives an external security opinion.

At the end, the user receives a clear verdict: safe, suspicious, or dangerous. If the link is dangerous, the system warns the user not to open it and provides a full report on a website.
```

## The Final Goal

The final goal is not to build a perfect antivirus.

The final goal is to build a working prototype that shows:

- We can analyze links automatically
- We can train a simple machine learning model
- We can connect to VirusTotal
- We can receive links from messages or emails
- We can warn users
- We can show clear reports on a website

That is enough for a strong university project.

## A Friendly Reminder

This project looks big, but it is just many small pieces connected together.

We can build it in small steps:

```text
First, check one link manually.
Then, save the result.
Then, show a report.
Then, add VirusTotal.
Then, receive links from Telegram or email.
```

If we follow the steps slowly, the project is very doable.
