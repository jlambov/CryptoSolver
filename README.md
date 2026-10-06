# CryptoSolver

CryptoSolver is an AI-assisted cryptographic analysis application built with
Python and Streamlit. I developed the project while experimenting with
AI-assisted software development and exploring how security controls can be
incorporated into an interactive analysis application.

The application provides tools for classical cipher analysis, automated key
testing, statistical and pattern analysis, and research into the Kryptos
sculpture and its K4 section.

## Features

- Caesar, Vigenère, and substitution cipher analysis
- Character-frequency analysis
- Bigram and trigram analysis
- Pattern recognition
- Automated and custom key testing
- Kryptos/K4-specific analysis tools
- Interactive visualizations
- Optional PostgreSQL storage for analysis sessions and results

## Security Considerations

Security was also part of the development process. The application includes:

- Input length limits to reduce resource-exhaustion risk
- Operation-specific rate limiting
- 30-minute inactive-session timeout
- Cryptographically secure random session identifiers
- Limits on parallel processing
- Input validation
- Sanitized error handling
- Removal of file-upload functionality to reduce attack surface

The project also includes a security assessment documenting security issues
identified during development and the corresponding mitigations.

## Architecture

The application uses a modular Python design:

- `app.py` — Streamlit application and user interface
- `ciphers.py` — cipher implementations
- `analysis.py` — statistical and frequency analysis
- `key_testing.py` — automated key testing
- `kryptos.py` — Kryptos-specific analysis
- `kryptos_visual.py` — Kryptos visualizations
- `rate_limiter.py` — rate limiting and session management
- `database.py` — optional PostgreSQL persistence
- `utils.py` — text-processing utilities

## Running Locally

Requires Python 3.11 or later.

Install the project dependencies and start the Streamlit application:

    pip install .
    streamlit run app.py

Database-backed features require a PostgreSQL connection configured through
the `DATABASE_URL` environment variable. The core analysis functionality can
run without the database.

## Project Background

CryptoSolver was developed as an AI-assisted security project using Replit.
My role included defining the application's functionality, iterating on the
Python/Streamlit implementation, testing the analysis workflows, and applying
security controls as the application evolved.

The project is intended for cryptographic analysis, experimentation, and
educational research.
