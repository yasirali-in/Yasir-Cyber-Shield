# YASIR CYBER SHIELD

A beginner-friendly cybersecurity semester project inspired by the workflow of VirusTotal. It includes a modern dashboard, file metadata scanner, optional VirusTotal API integration, URL and IP reputation lookup, learning modules, and an interactive quiz.

## Technology
- Frontend: HTML5, CSS3, Vanilla JavaScript
- Backend: Node.js, Express.js
- Security / utilities: Helmet, express-rate-limit, Multer, SHA-256
- Database: None

## Requirements
- Node.js 20 or newer
- npm
- Internet connection for optional VirusTotal API access

## Run in VS Code (Windows)
1. Extract the ZIP file.
2. Open the `yasir-cyber-shield` folder in VS Code.
3. Open Terminal → New Terminal.
4. Install dependencies:
   ```bash
   npm install
   ```
5. Copy `.env.example` to a new file named `.env`.
6. (Optional) Add your VirusTotal Community API key to `.env`:
   ```env
   VT_API_KEY=your_api_key_here
   ```
   Keep this key private. Never paste it into `public/app.js` or upload `.env` to GitHub.
7. Start the server:
   ```bash
   npm start
   ```
8. Open `http://localhost:3000` in your browser.

## Modes
### Demo mode (works without an API key)
- File upload calculates file size, MIME type and SHA-256 locally on the server.
- URL checker validates URL syntax only.
- IP lookup validates IP address syntax only.
- The interface clearly labels these outputs as demo mode; it does not claim to detect malware.

### VirusTotal API mode
Add your own API key to `.env` and restart the server. The backend can submit files (up to 32 MB) and retrieve analysis status, and look up URL/IP reputation. VirusTotal public API quotas and terms apply.

**Privacy warning:** Submitting a file or indicator to VirusTotal may share it with VirusTotal and its security partners and add it to its dataset. Never submit confidential, private, proprietary or personally identifiable information. The app asks for consent before file upload. Only submit files you are authorized to share.

## Project structure
```text
yasir-cyber-shield/
├── public/
│   ├── index.html
│   ├── styles.css
│   └── app.js
├── server.js
├── package.json
├── .env.example
├── .gitignore
└── README.md
```

## Suggested semester-project modules
1. Dashboard and navigation
2. File upload and SHA-256 hashing
3. VirusTotal API integration
4. URL and IP reputation lookup
5. Cybersecurity learning modules
6. MCQ quiz and feedback
7. Input validation, rate limiting and security headers

## Important limitations
- This is an educational project, not a replacement for antivirus or endpoint protection.
- The app does not execute uploaded files or perform dynamic malware sandboxing.
- Demo mode does not detect malware.
- VirusTotal API availability, quotas and permitted use depend on the account and current terms.
- The project uses in-memory processing only; it does not save uploaded files or scan history in a database.

## Reference
VirusTotal API v3 documentation: https://docs.virustotal.com/reference/overview
