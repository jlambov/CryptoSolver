"""
Rate limiting implementation for the Cryptographic Analysis Tool
Provides simple, effective rate limiting without requiring authentication
Includes session timeout management
"""

import time
from typing import Dict, Optional
import streamlit as st
from datetime import datetime, timedelta
import streamlit.components.v1 as components

class RateLimiter:
    """Rate limiter with session timeout management"""
    
    def __init__(self):
        # Rate limits for different operations
        self.limits = {
            'comprehensive_attack': {'requests': 3, 'window': 3600},  # 3 attacks per hour
            'specific_key_test': {'requests': 10, 'window': 3600},    # 10 specific tests per hour
            'cipher_decrypt': {'requests': 50, 'window': 3600},       # 50 decryptions per hour
            'statistical_analysis': {'requests': 20, 'window': 3600}, # 20 analyses per hour
            'text_input': {'requests': 100, 'window': 3600}          # 100 text inputs per hour
        }
        
        # Session timeout: 30 minutes of inactivity
        self.session_timeout = 1800  # 30 minutes in seconds
        
        # Initialize session state for rate limiting if not exists
        if 'rate_limit_data' not in st.session_state:
            st.session_state.rate_limit_data = {}
        
        # Initialize session activity tracking
        if 'last_activity' not in st.session_state:
            st.session_state.last_activity = time.time()
        
        if 'session_created' not in st.session_state:
            st.session_state.session_created = time.time()
    
    def check_session_timeout(self) -> tuple[bool, str]:
        """
        Check if session has timed out due to inactivity
        Returns: (session_valid, message)
        """
        current_time = time.time()
        
        # Check if session has timed out
        if current_time - st.session_state.last_activity > self.session_timeout:
            return False, "Session expired due to inactivity. Please refresh the page to continue."
        
        return True, "Session active"
    
    def update_activity(self):
        """Update last activity timestamp"""
        st.session_state.last_activity = time.time()
    
    def get_session_info(self) -> Dict[str, str]:
        """Get session information for display"""
        current_time = time.time()
        session_age = current_time - st.session_state.session_created
        time_since_activity = current_time - st.session_state.last_activity
        time_until_timeout = max(0, self.session_timeout - time_since_activity)
        
        return {
            'session_age': self._format_duration(session_age),
            'time_until_timeout': self._format_duration(time_until_timeout),
            'last_activity': self._format_duration(time_since_activity) + " ago"
        }
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human readable format"""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            return f"{int(seconds/60)}m {int(seconds%60)}s"
        else:
            hours = int(seconds / 3600)
            minutes = int((seconds % 3600) / 60)
            return f"{hours}h {minutes}m"
    
    def check_rate_limit(self, operation: str, session_id: str) -> tuple[bool, str, int]:
        """
        Check if operation is within rate limits and session is valid
        Returns: (allowed, message, remaining_requests)
        """
        # First check session timeout
        session_valid, session_message = self.check_session_timeout()
        if not session_valid:
            return False, session_message, 0
        
        # Update activity on any operation check
        self.update_activity()
        
        if operation not in self.limits:
            return True, "Operation allowed", 999
        
        limit_config = self.limits[operation]
        max_requests = limit_config['requests']
        window_seconds = limit_config['window']
        
        current_time = time.time()
        key = f"{session_id}:{operation}"
        
        # Get current requests for this key
        if key not in st.session_state.rate_limit_data:
            st.session_state.rate_limit_data[key] = []
        
        requests = st.session_state.rate_limit_data[key]
        
        # Remove old requests outside the window
        requests = [req_time for req_time in requests if current_time - req_time < window_seconds]
        st.session_state.rate_limit_data[key] = requests
        
        # Check if limit exceeded
        if len(requests) >= max_requests:
            window_hours = window_seconds / 3600
            remaining_time = window_seconds - (current_time - min(requests))
            remaining_minutes = int(remaining_time / 60)
            
            message = f"Rate limit exceeded. Maximum {max_requests} {operation.replace('_', ' ')} operations per {window_hours:.0f} hour(s). Try again in {remaining_minutes} minutes."
            return False, message, 0
        
        # Add current request
        requests.append(current_time)
        st.session_state.rate_limit_data[key] = requests
        
        remaining = max_requests - len(requests)
        return True, f"Operation allowed. {remaining} remaining in current window.", remaining
    
    def get_usage_stats(self, session_id: str) -> Dict[str, Dict]:
        """Get current usage statistics for a session"""
        stats = {}
        current_time = time.time()
        
        for operation, config in self.limits.items():
            key = f"{session_id}:{operation}"
            window_seconds = config['window']
            
            if key in st.session_state.rate_limit_data:
                requests = st.session_state.rate_limit_data[key]
                # Count recent requests
                recent_requests = [req for req in requests if current_time - req < window_seconds]
                
                stats[operation] = {
                    'used': len(recent_requests),
                    'limit': config['requests'],
                    'remaining': config['requests'] - len(recent_requests),
                    'window_hours': config['window'] / 3600
                }
            else:
                stats[operation] = {
                    'used': 0,
                    'limit': config['requests'],
                    'remaining': config['requests'],
                    'window_hours': config['window'] / 3600
                }
        
        return stats

def rate_limited(operation: str):
    """Decorator for rate limiting functions"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            if 'rate_limiter' not in st.session_state:
                st.session_state.rate_limiter = RateLimiter()
            
            session_id = st.session_state.get('session_id', 'anonymous')
            rate_limiter = st.session_state.rate_limiter
            
            allowed, message, remaining = rate_limiter.check_rate_limit(operation, session_id)
            
            if not allowed:
                st.error(f"⚠️ {message}")
                return None
            
            # Show rate limit info for heavy operations
            if operation in ['comprehensive_attack', 'specific_key_test']:
                st.info(f"ℹ️ {message}")
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator

def show_rate_limit_status():
    """Display current rate limit status and session info in sidebar"""
    if 'rate_limiter' not in st.session_state:
        st.session_state.rate_limiter = RateLimiter()
    
    session_id = st.session_state.get('session_id', 'anonymous')
    rate_limiter = st.session_state.rate_limiter
    
    # Check session status
    session_valid, session_message = rate_limiter.check_session_timeout()
    
    st.sidebar.markdown("---")
    
    # Show session status with live countdown
    st.sidebar.markdown("**⏱️ Session Status**")
    if session_valid:
        session_info = rate_limiter.get_session_info()
        st.sidebar.write(f"🟢 Active")
        
        # Calculate remaining seconds for JavaScript countdown
        current_time = time.time()
        time_since_activity = current_time - st.session_state.last_activity
        remaining_seconds = int(1800 - time_since_activity)  # 1800 = 30 minutes
        
        # Create HTML with embedded JavaScript that works in Streamlit
        countdown_component = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    margin: 0;
                    padding: 0;
                    font-family: 'Source Sans Pro', sans-serif;
                    background: transparent;
                }}
                .countdown-container {{
                    font-family: monospace;
                    font-weight: bold;
                    font-size: 13px;
                    padding: 2px 0;
                    color: white;
                }}
            </style>
        </head>
        <body>
            <div class="countdown-container">
                Timeout in: <span id="countdown-timer" style="color: #00aa00;">{session_info['time_until_timeout']}</span>
            </div>
            
            <script>
                let remainingSeconds = {remaining_seconds};
                
                function updateCountdown() {{
                    const timer = document.getElementById('countdown-timer');
                    if (!timer) return;
                    
                    if (remainingSeconds <= 0) {{
                        timer.textContent = '0s (EXPIRED)';
                        timer.style.color = '#ff0000';
                        return;
                    }}
                    
                    const minutes = Math.floor(remainingSeconds / 60);
                    const seconds = remainingSeconds % 60;
                    const timeString = minutes > 0 ? minutes + 'm ' + seconds + 's' : seconds + 's';
                    
                    timer.textContent = timeString;
                    
                    // Change color based on remaining time
                    if (remainingSeconds < 300) {{ // Less than 5 minutes
                        timer.style.color = '#ff4444';
                    }} else if (remainingSeconds < 600) {{ // Less than 10 minutes
                        timer.style.color = '#ffaa00';
                    }} else {{
                        timer.style.color = '#00aa00';
                    }}
                    
                    remainingSeconds--;
                }}
                
                // Update immediately and then every second
                updateCountdown();
                const interval = setInterval(updateCountdown, 1000);
                
                // Clean up interval when component is destroyed
                window.addEventListener('beforeunload', function() {{
                    clearInterval(interval);
                }});
            </script>
        </body>
        </html>
        """
        
        # Display the countdown component in sidebar with smaller height
        with st.sidebar:
            components.html(countdown_component, height=25, scrolling=False)
        
        with st.sidebar.expander("Session Details"):
            st.write(f"Session age: {session_info['session_age']}")
            st.write(f"Last activity: {session_info['last_activity']}")
            st.write("Timeout: 30 minutes of inactivity")
            st.write("Live countdown updates every second")
    else:
        st.sidebar.write("🔴 Session Expired")
        st.sidebar.error("Please refresh to continue")
        return  # Don't show rate limits if session expired
    
    # Show rate limits
    stats = rate_limiter.get_usage_stats(session_id)
    st.sidebar.markdown("**🚦 Rate Limits**")
    
    # Show key limits
    key_operations = ['comprehensive_attack', 'specific_key_test']
    
    for op in key_operations:
        if op in stats:
            stat = stats[op]
            op_name = op.replace('_', ' ').title()
            
            # Color code based on usage
            if stat['remaining'] == 0:
                color = "🔴"
            elif stat['remaining'] <= 1:
                color = "🟡"
            else:
                color = "🟢"
            
            st.sidebar.write(f"{color} {op_name}: {stat['remaining']}/{stat['limit']}")
    
    # Show expandable detailed stats
    with st.sidebar.expander("📊 Detailed Usage"):
        for operation, stat in stats.items():
            op_name = operation.replace('_', ' ').title()
            st.write(f"**{op_name}**")
            st.write(f"Used: {stat['used']}/{stat['limit']} (per {stat['window_hours']:.0f}h)")
            if stat['remaining'] > 0:
                st.write(f"Remaining: {stat['remaining']}")
            else:
                st.write("❌ Limit reached")
            st.write("---")

def check_and_enforce_rate_limit(operation: str) -> bool:
    """
    Check rate limit and session timeout, show error if exceeded
    Returns True if allowed, False if blocked
    """
    if 'rate_limiter' not in st.session_state:
        st.session_state.rate_limiter = RateLimiter()
    
    session_id = st.session_state.get('session_id', 'anonymous')
    rate_limiter = st.session_state.rate_limiter
    
    allowed, message, remaining = rate_limiter.check_rate_limit(operation, session_id)
    
    if not allowed:
        if "Session expired" in message:
            st.error(f"⏱️ {message}")
            st.info("Your session has expired due to 30 minutes of inactivity. Please refresh the page to start a new session.")
            if st.button("🔄 Refresh Page"):
                st.rerun()
        else:
            st.error(f"⚠️ {message}")
            st.info("Rate limiting helps ensure fair usage and system stability.")
        return False
    
    return True

def force_session_refresh_if_expired():
    """Force page refresh if session has expired"""
    if 'rate_limiter' not in st.session_state:
        st.session_state.rate_limiter = RateLimiter()
    
    rate_limiter = st.session_state.rate_limiter
    session_valid, session_message = rate_limiter.check_session_timeout()
    
    if not session_valid:
        st.error(f"⏱️ {session_message}")
        st.info("Your session has expired. Please refresh the page to continue.")
        st.markdown("**Click the refresh button in your browser or press F5**")
        st.stop()  # Stop execution to prevent further operations