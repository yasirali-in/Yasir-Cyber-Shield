# Semester Project Report Outline — YASIR CYBER SHIELD

## 1. Introduction
Yasir Cyber Shield is a web-based educational cybersecurity platform. It provides basic file metadata analysis, optional third-party reputation lookup, and cybersecurity learning resources.

## 2. Problem Statement
Students and everyday users need a simple learning environment to understand file hashes, suspicious links, IP reputation, malware concepts and safe online behavior.

## 3. Objectives
- Build a responsive cybersecurity dashboard.
- Accept files safely without executing them.
- Calculate SHA-256 file hashes.
- Integrate VirusTotal API optionally through a protected backend.
- Provide URL and IP reputation lookup interfaces.
- Teach cybersecurity concepts through lessons and quizzes.
- Demonstrate basic web security practices.

## 4. Scope
The application is intended for education and authorized use. It is not a commercial antivirus product and does not guarantee that a file or indicator is safe.

## 5. System Architecture
Browser (HTML/CSS/JavaScript) → Express REST API → validation and SHA-256 processing → optional VirusTotal API → JSON response → browser results.

## 6. Functional Requirements
- Dashboard navigation
- File selection, consent and upload
- SHA-256 calculation and file metadata
- Optional VirusTotal analysis submission and status retrieval
- URL report lookup
- IP report lookup
- Course modules and quiz

## 7. Non-Functional Requirements
- Responsive user interface
- Server-side validation
- API key stored in environment variables
- Upload size limit
- Rate limiting
- No database or permanent file storage

## 8. Testing Suggestions
- Test with a small harmless text file.
- Test upload with no API key (demo mode).
- Test file larger than 32 MB.
- Test invalid URL and invalid IP input.
- Test mobile and desktop layouts.
- Test API-key error handling.
- Never test with live malware on a personal computer.

## 9. Future Enhancements
- User authentication and role-based access
- Scan history with a database
- Exportable PDF reports
- Additional threat-intelligence sources
- Admin dashboard and audit logs

## 10. Conclusion
The project demonstrates frontend/backend development, secure file handling, cryptographic hashing, third-party API integration and cybersecurity awareness.
