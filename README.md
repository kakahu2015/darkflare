# 🌒 DarkFlare

A stealthy TCP-over-CDN tunnel that keeps your connections cozy and comfortable behind Cloudflare's welcoming embrace.

## 🤔 What is this sorcery?

DarkFlare is a clever little tool that disguises your TCP traffic as innocent HTTPS requests, letting them pass through corporate firewalls like a VIP at a nightclub. It's like a tunnel, but with more style and less dirt.

It has two parts: a client-side proxy (darkflare-client) that encodes TCP data into HTTPS requests and sends it to a Cloudflare-protected domain, and a server-side proxy (darkflare-server) that decodes the requests and forwards the data to a local service (like SSH on port 22). It’s protocol-agnostic, secure, and uses Cloudflare's encrypted infrastructure, making it stealthy and scalable for accessing internal resources or bypassing network restrictions.

When using this remember the traffic over the tunnel is only as secure as the Cloudflare protection. Use your own encryption.

## 🧱  What is TBTB?
I think CDNs like Cloudflare, Akamai, Fastly, Akamai, and Amazon CloudFront are considered "Too Big to Block" (TBTB) because they power millions of websites globally, including critical infrastructure like government, healthcare, and financial services. Its shared IP architecture means blocking one malicious site can unintentionally block thousands of legitimate ones, creating massive collateral damage. With a vast global network of data centers, Cloudflare’s infrastructure is highly resilient, making it nearly impossible to disrupt without severe technical and logistical challenges. Additionally, blocking Cloudflare would disrupt economies, hinder online commerce, and provoke public and political backlash, as its services are deeply embedded in modern internet functionality. As a neutral service provider, blocking it is akin to shutting down a utility vital to the global web.

## ⁇  Usecases
ssh, rdp, or anything tcp to bypass restrictive firewalls or state controled internet.
Tunneling ppp or other vpn services that leverage TCP.

## ✨ Features

- **Sneaky TCP Tunneling**: Wraps your TCP connections in a fashionable HTTPS outfit
- **Cloudflare Integration**: Because who doesn't want their traffic to look like it's just visiting Cloudflare?
- **Debug Mode**: For when things go wrong and you need to know why (spoiler: it's always DNS)
- **Session Management**: Keeps your connections organized like a Type A personality
- **TLS Security**: Because we're sneaky, not reckless

## ☠️ Pending Features
- **Random File Requests**: Randomize the file names for the GET requests with jpegs and php.

## 🚀 Quick Start

### Run the client:
bash
Run the client
./bin/darkflare-client -h ssh.foo.host -l 2222 -d       

Add -d flag for debug.

./bin/darkflare-server -d localhost:22 -p 8080 -debug

Add -debug for the server debug messages.

ssh user@localhost -p 2222


## ⚠️ Disclaimer

This tool is for educational purposes only. Please don't use it to bypass your company's firewall - your IT department has enough headaches already.

## 🤝 Contributing

Found a bug? Want to add a feature? PRs are welcome! Just remember:
- Keep it clean
- Keep it clever
- Keep it working

## 📜 License

MIT License - Because sharing is caring, but attribution is nice.

---
*Built with ❤️ and a healthy dose of mischief*
