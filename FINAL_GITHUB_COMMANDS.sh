#!/bin/bash
# Run these commands after adding SSH key to GitHub

# Remove any lock files
rm -f .git/index.lock .git/config.lock

# Update remote to use SSH 
git remote set-url origin git@github.com:jlambov/CryptoSolver.git

# Test SSH connection (should show: Hi jlambov! You've successfully authenticated)
ssh -T git@github.com

# Add all changes and commit
git add .
git commit -m "Update: Enhanced Kryptos analysis with multi-key testing

- Added comprehensive key testing system (HOWS, UNDERGRUUND, DESPARATLY, IQLUSION)
- Implemented rate limiting with 30-minute session timeout
- Added real-time countdown timer in sidebar
- Enhanced security with OWASP Top 10 compliance
- PostgreSQL database integration for analysis storage
- Educational content with complete Kryptos information"

# Push to GitHub
git push origin main

echo "Successfully pushed to GitHub!"