# 🌒 DarkFlare

A stealthy TCP-over-CDN tunnel that keeps your connections cozy and comfortable behind Cloudflare's welcoming embrace.

## 🤔 What is this sorcery?

DarkFlare is a clever little tool that disguises your TCP traffic as innocent HTTPS requests, letting them pass through corporate firewalls like a VIP at a nightclub. It's like a tunnel, but with more style and less dirt.

## ✨ Features

- **Sneaky TCP Tunneling**: Wraps your TCP connections in a fashionable HTTPS outfit
- **Cloudflare Integration**: Because who doesn't want their traffic to look like it's just visiting Cloudflare?
- **Debug Mode**: For when things go wrong and you need to know why (spoiler: it's always DNS)
- **Session Management**: Keeps your connections organized like a Type A personality
- **TLS Security**: Because we're sneaky, not reckless

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
