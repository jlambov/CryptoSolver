"""
Rate limiting implementation for the Cryptographic Analysis Tool.

Provides per-session, operation-specific rate limiting and
inactive-session timeout management.
"""

import time
from typing import Dict

import streamlit as st


class RateLimiter:
    """Rate limiter with session timeout management."""

    def __init__(self):
        # Rate limits for different operations
        self.limits = {
            "comprehensive_attack": {"requests": 3, "window": 3600},
            "specific_key_test": {"requests": 10, "window": 3600},
            "cipher_decrypt": {"requests": 50, "window": 3600},
            "statistical_analysis": {"requests": 20, "window": 3600},
            "text_input": {"requests": 100, "window": 3600},
        }

        # Session timeout: 30 minutes of inactivity
        self.session_timeout = 1800

        # Initialize session state for rate limiting
        if "rate_limit_data" not in st.session_state:
            st.session_state.rate_limit_data = {}

        # Initialize session activity tracking
        if "last_activity" not in st.session_state:
            st.session_state.last_activity = time.time()

        if "session_created" not in st.session_state:
            st.session_state.session_created = time.time()

    def check_session_timeout(self) -> tuple[bool, str]:
        """
        Check whether the session has timed out due to inactivity.

        Returns:
            Tuple containing session validity and a status message.
        """
        current_time = time.time()

        if current_time - st.session_state.last_activity > self.session_timeout:
            return (
                False,
                "Session expired due to inactivity. "
                "Please refresh the page to continue.",
            )

        return True, "Session active"

    def update_activity(self):
        """Update the last activity timestamp."""
        st.session_state.last_activity = time.time()

    def get_session_info(self) -> Dict[str, str]:
        """Get session information for display."""
        current_time = time.time()
        session_age = current_time - st.session_state.session_created
        time_since_activity = current_time - st.session_state.last_activity
        time_until_timeout = max(
            0,
            self.session_timeout - time_since_activity,
        )

        return {
            "session_age": self._format_duration(session_age),
            "time_until_timeout": self._format_duration(time_until_timeout),
            "last_activity": (
                self._format_duration(time_since_activity) + " ago"
            ),
        }

    def _format_duration(self, seconds: float) -> str:
        """Format a duration in human-readable form."""
        if seconds < 60:
            return f"{int(seconds)}s"

        if seconds < 3600:
            return f"{int(seconds / 60)}m {int(seconds % 60)}s"

        hours = int(seconds / 3600)
        minutes = int((seconds % 3600) / 60)
        return f"{hours}h {minutes}m"

    def check_rate_limit(
        self,
        operation: str,
        session_id: str,
    ) -> tuple[bool, str, int]:
        """
        Check whether an operation is within its rate limit.

        Returns:
            Tuple containing whether the operation is allowed,
            a status message, and the number of remaining requests.
        """
        # Check session timeout first
        session_valid, session_message = self.check_session_timeout()

        if not session_valid:
            return False, session_message, 0

        # A rate-limited operation counts as session activity
        self.update_activity()

        if operation not in self.limits:
            return True, "Operation allowed", 999

        limit_config = self.limits[operation]
        max_requests = limit_config["requests"]
        window_seconds = limit_config["window"]

        current_time = time.time()
        key = f"{session_id}:{operation}"

        if key not in st.session_state.rate_limit_data:
            st.session_state.rate_limit_data[key] = []

        requests = st.session_state.rate_limit_data[key]

        # Remove requests outside the current rate-limit window
        requests = [
            request_time
            for request_time in requests
            if current_time - request_time < window_seconds
        ]

        st.session_state.rate_limit_data[key] = requests

        if len(requests) >= max_requests:
            window_hours = window_seconds / 3600
            remaining_time = (
                window_seconds - (current_time - min(requests))
            )
            remaining_minutes = max(0, int(remaining_time / 60))

            message = (
                f"Rate limit exceeded. Maximum {max_requests} "
                f"{operation.replace('_', ' ')} operations per "
                f"{window_hours:.0f} hour(s). "
                f"Try again in {remaining_minutes} minutes."
            )

            return False, message, 0

        # Record the current request
        requests.append(current_time)
        st.session_state.rate_limit_data[key] = requests

        remaining = max_requests - len(requests)

        return (
            True,
            f"Operation allowed. "
            f"{remaining} remaining in current window.",
            remaining,
        )

    def get_usage_stats(self, session_id: str) -> Dict[str, Dict]:
        """Get current rate-limit usage statistics for a session."""
        stats = {}
        current_time = time.time()

        for operation, config in self.limits.items():
            key = f"{session_id}:{operation}"
            window_seconds = config["window"]

            if key in st.session_state.rate_limit_data:
                requests = st.session_state.rate_limit_data[key]

                recent_requests = [
                    request_time
                    for request_time in requests
                    if current_time - request_time < window_seconds
                ]

                stats[operation] = {
                    "used": len(recent_requests),
                    "limit": config["requests"],
                    "remaining": (
                        config["requests"] - len(recent_requests)
                    ),
                    "window_hours": window_seconds / 3600,
                }
            else:
                stats[operation] = {
                    "used": 0,
                    "limit": config["requests"],
                    "remaining": config["requests"],
                    "window_hours": window_seconds / 3600,
                }

        return stats


def rate_limited(operation: str):
    """Decorator for rate-limited functions."""

    def decorator(func):
        def wrapper(*args, **kwargs):
            if "rate_limiter" not in st.session_state:
                st.session_state.rate_limiter = RateLimiter()

            session_id = st.session_state.get(
                "session_id",
                "anonymous",
            )
            rate_limiter = st.session_state.rate_limiter

            allowed, message, _ = rate_limiter.check_rate_limit(
                operation,
                session_id,
            )

            if not allowed:
                st.error(f"⚠️ {message}")
                return None

            if operation in [
                "comprehensive_attack",
                "specific_key_test",
            ]:
                st.info(f"ℹ️ {message}")

            return func(*args, **kwargs)

        return wrapper

    return decorator


def show_rate_limit_status():
    """Display current rate-limit and session information."""
    if "rate_limiter" not in st.session_state:
        st.session_state.rate_limiter = RateLimiter()

    session_id = st.session_state.get(
        "session_id",
        "anonymous",
    )
    rate_limiter = st.session_state.rate_limiter

    session_valid, _ = rate_limiter.check_session_timeout()

    st.sidebar.markdown("---")
    st.sidebar.markdown("**⏱️ Session Status**")

    if session_valid:
        session_info = rate_limiter.get_session_info()

        st.sidebar.write("🟢 Active")
        st.sidebar.write(
            "Inactive-session timeout in: "
            f"{session_info['time_until_timeout']}"
        )

        with st.sidebar.expander("Session Details"):
            st.write(
                f"Session age: {session_info['session_age']}"
            )
            st.write(
                f"Last activity: "
                f"{session_info['last_activity']}"
            )
            st.write("Timeout: 30 minutes of inactivity")

    else:
        st.sidebar.write("🔴 Session Expired")
        st.sidebar.error("Please refresh to continue")
        return

    stats = rate_limiter.get_usage_stats(session_id)

    st.sidebar.markdown("**🚦 Rate Limits**")

    key_operations = [
        "comprehensive_attack",
        "specific_key_test",
    ]

    for operation in key_operations:
        if operation in stats:
            stat = stats[operation]
            operation_name = operation.replace("_", " ").title()

            if stat["remaining"] == 0:
                indicator = "🔴"
            elif stat["remaining"] <= 1:
                indicator = "🟡"
            else:
                indicator = "🟢"

            st.sidebar.write(
                f"{indicator} {operation_name}: "
                f"{stat['remaining']}/{stat['limit']}"
            )

    with st.sidebar.expander("📊 Detailed Usage"):
        for operation, stat in stats.items():
            operation_name = operation.replace("_", " ").title()

            st.write(f"**{operation_name}**")
            st.write(
                f"Used: {stat['used']}/{stat['limit']} "
                f"(per {stat['window_hours']:.0f}h)"
            )

            if stat["remaining"] > 0:
                st.write(
                    f"Remaining: {stat['remaining']}"
                )
            else:
                st.write("❌ Limit reached")

            st.write("---")


def check_and_enforce_rate_limit(operation: str) -> bool:
    """
    Check rate limit and session timeout.

    Returns:
        True if the operation is allowed, otherwise False.
    """
    if "rate_limiter" not in st.session_state:
        st.session_state.rate_limiter = RateLimiter()

    session_id = st.session_state.get(
        "session_id",
        "anonymous",
    )
    rate_limiter = st.session_state.rate_limiter

    allowed, message, _ = rate_limiter.check_rate_limit(
        operation,
        session_id,
    )

    if not allowed:
        if "Session expired" in message:
            st.error(f"⏱️ {message}")
            st.info(
                "Your session has expired due to 30 minutes "
                "of inactivity. Please refresh the page to "
                "start a new session."
            )

            if st.button("🔄 Refresh Page"):
                st.rerun()
        else:
            st.error(f"⚠️ {message}")
            st.info(
                "Rate limiting helps ensure fair usage "
                "and system stability."
            )

        return False

    return True


def force_session_refresh_if_expired():
    """Stop processing when the current session has expired."""
    if "rate_limiter" not in st.session_state:
        st.session_state.rate_limiter = RateLimiter()

    rate_limiter = st.session_state.rate_limiter
    session_valid, session_message = (
        rate_limiter.check_session_timeout()
    )

    if not session_valid:
        st.error(f"⏱️ {session_message}")
        st.info(
            "Your session has expired. "
            "Please refresh the page to continue."
        )
        st.markdown(
            "**Click the refresh button in your browser "
            "or press F5**"
        )
        st.stop()
