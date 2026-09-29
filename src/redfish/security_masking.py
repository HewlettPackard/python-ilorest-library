###
# Copyright 2025 Hewlett Packard Enterprise, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###

# -*- coding: utf-8 -*-
"""Centralized security masking framework for iLORest"""

import json
import re
import copy
from typing import Dict, List, Any, Union, Optional


class SecurityMasker:
    """Centralized framework for masking sensitive information in logs and outputs."""

    # Default mask character
    MASK_VALUE = "******"

    # Number of characters to show for partial masking
    PARTIAL_MASK_SHOW_CHARS = 4

    # Sensitive command-line argument patterns
    SENSITIVE_CLI_KEYWORDS = {
        "--password",
        "--pass",
        "-p",
        "--pwd",
        "--token",
        "--auth-token",
        "--session-token",
        "--key",
        "--api-key",
        "--secret",
        "--credential",
        "--cert-key",
        "--private-key",
        "--passphrase",
        "--sessionkey",
        "--auth",
        "--authorization",
        "--filepass",
        "--backup-password",
        "--biospassword",
        "--owner_auth",
    }

    # Fields requiring COMPLETE masking (no characters visible)
    COMPLETE_MASK_FIELDS = {
        "password",
        "oldpassword",
        "newpassword",
        "currentpassword",
        "passwd",
        "pwd",
        "pass",
        "passphrase",
        "secret",
        "client_secret",
        "private_key",
        "privatekey",
        "cert_key",
        "certkey",
        "pin",
        "otp",
        "totp",
        "mfa_token",
        "csrf_token",
        "csrftoken",
        "owner_auth",
    }

    # Fields allowing PARTIAL masking (last 4-6 chars visible for debugging)
    PARTIAL_MASK_FIELDS = {
        "token",
        "auth_token",
        "authtoken",
        "session_token",
        "sessiontoken",
        "access_token",
        "accesstoken",
        "refresh_token",
        "refreshtoken",
        "bearer_token",
        "api_key",
        "apikey",
        "sessionkey",
        "session_key",
        "credential",
        "credentials",
        "appid",
        "app_id",
        "applicationid",
        "application_id",
    }

    # Headers requiring COMPLETE masking
    COMPLETE_MASK_HEADERS = {
        "authorization",  # Often contains Basic auth with password
        "www-authenticate",
        "proxy-authorization",
        "cookie",
        "set-cookie",  # May contain sensitive session data
    }

    # Headers allowing PARTIAL masking (for debugging/correlation)
    PARTIAL_MASK_HEADERS = {
        "x-auth-token",
        "x-session-token",
        "x-api-key",
        "api-key",
        "bearer",  # When separate from Authorization header
        "x-session-id",
        "session-id",
    }

    # All sensitive headers (union of complete and partial)
    SENSITIVE_HEADERS = (
        COMPLETE_MASK_HEADERS
        | PARTIAL_MASK_HEADERS
        | {"authentication", "basic", "digest", "oauth", "jwt", "x-csrf-token", "x-request-id"}
    )

    # All sensitive body fields (union of complete and partial)
    SENSITIVE_BODY_FIELDS = COMPLETE_MASK_FIELDS | PARTIAL_MASK_FIELDS | {"auth", "authorization"}

    # URL parameter patterns that might contain sensitive data
    SENSITIVE_URL_PARAMS = {"password", "token", "key", "secret", "auth", "session", "credential", "pass", "pwd"}

    @classmethod
    def mask_command_arguments(cls, args: List[str]) -> List[str]:
        """
        Mask sensitive information in command-line arguments.

        Args:
            args: List of command-line arguments

        Returns:
            List of arguments with sensitive values masked

        Example:
            >>> SecurityMasker.mask_command_arguments(['--user', 'admin', '--password', 'MyP@ss'])
            ['--user', 'admin', '--password', '******']
        """
        if not args:
            return args

        masked_args = []
        i = 0

        while i < len(args):
            arg = args[i]

            # Check for inline sensitive arguments (--password=value)
            if cls._has_inline_sensitive_value(arg):
                masked_args.append(cls._mask_inline_argument(arg))
                i += 1
                continue

            # Check if current arg is a sensitive flag
            if cls._is_sensitive_cli_flag(arg):
                masked_args.append(arg)  # Keep the flag
                # Mask the next argument if it exists and isn't another flag
                if i + 1 < len(args) and not args[i + 1].startswith("-"):
                    i += 1  # Move to the next argument
                    masked_args.append(cls.MASK_VALUE)  # Mask the value
                i += 1
                continue

            # Keep non-sensitive arguments as-is
            masked_args.append(arg)
            i += 1

        return masked_args

    @classmethod
    def mask_http_headers(
        cls, headers: Union[Dict[str, str], List[tuple], Any]
    ) -> Union[Dict[str, str], List[tuple], str]:
        """
        Mask sensitive information in HTTP headers.

        Args:
            headers: HTTP headers in various formats (dict, list of tuples, or other)

        Returns:
            Headers with sensitive values masked

        Examples:
            # dict format
            >>> SecurityMasker.mask_http_headers({'Authorization': 'Basic abc123', 'Accept': 'application/json'})
            {'Authorization': '******', 'Accept': 'application/json'}

            # list-of-tuples format
            >>> SecurityMasker.mask_http_headers([('Authorization', 'Bearer abcd'), ('Host', 'example')])
            [('Authorization', '******'), ('Host', 'example')]
        """
        if not headers:
            return headers

        try:
            # Handle dictionary format
            if isinstance(headers, dict):
                return cls._mask_headers_dict(headers)

            # Handle list of tuples format
            elif isinstance(headers, (list, tuple)):
                return cls._mask_headers_list(headers)

            # Handle string representation of headers
            elif isinstance(headers, str):
                return cls._mask_headers_string(headers)

            # Handle other object types (e.g., HTTPMessage)
            else:
                return cls._mask_headers_object(headers)

        except Exception:
            # If masking fails, return a safe placeholder
            return "[HEADERS MASKED DUE TO PROCESSING ERROR]"

    @classmethod
    def mask_simple_body(cls, body: Union[str, bytes, Dict[str, Any]]) -> Union[str, bytes, Dict[str, Any]]:
        """
        Mask sensitive information in simple HTTP request/response bodies.

        This method handles basic body masking for simple payloads.
        For complex bodies with advanced JSON parsing and error handling,
        use mask_complex_body() instead.

        Args:
            body: Request/response body in various formats

        Returns:
            Body with sensitive values masked

        Examples:
            # JSON string
            >>> SecurityMasker.mask_simple_body('{"password":"secret"}')
            '{"password":"******"}'

            # dict
            >>> SecurityMasker.mask_simple_body({"token": "abcd"})
            {"token": "******"}
        """
        if not body:
            return body

        try:
            # Handle string body (likely JSON)
            if isinstance(body, str):
                return cls._mask_string_body(body)

            # Handle bytes body
            elif isinstance(body, bytes):
                return cls._mask_bytes_body(body)

            # Handle dictionary body
            elif isinstance(body, dict):
                return cls._mask_dict_body(body)

            # Handle other types
            else:
                return body

        except Exception:
            # If masking fails, return original or safe placeholder
            if isinstance(body, (str, bytes)):
                return "[BODY MASKED DUE TO PROCESSING ERROR]"
            return body

    @classmethod
    def mask_url_parameters(cls, url: str) -> str:
        """
        Mask sensitive information in URL parameters.

        Args:
            url: URL string that may contain parameters

        Returns:
            URL with sensitive parameter values masked

        Example:
            >>> SecurityMasker.mask_url_parameters('https://api.example.com/login?user=admin&password=1234')
            'https://api.example.com/login?user=admin&password=******'
        """
        if not url or "?" not in url:
            return url

        try:
            base_url, params = url.split("?", 1)
            param_pairs = params.split("&")
            masked_pairs = []

            for pair in param_pairs:
                if "=" in pair:
                    key, value = pair.split("=", 1)
                    if any(sensitive in key.lower() for sensitive in cls.SENSITIVE_URL_PARAMS):
                        masked_pairs.append(f"{key}={cls.MASK_VALUE}")
                    else:
                        masked_pairs.append(pair)
                else:
                    masked_pairs.append(pair)

            return f"{base_url}?{'&'.join(masked_pairs)}"

        except Exception:
            return url

    @classmethod
    def mask_complex_body(cls, body: Union[str, bytes, Dict[str, Any]]) -> Union[str, bytes]:
        """
        Mask sensitive information in complex HTTP request/response bodies for logging.

        This is a specialized method for complex body masking that handles:
        - Advanced JSON parsing with error recovery
        - Automatic encoding/decoding (str ↔ bytes)
        - Type preservation (returns same type as input)
        - Graceful error handling to ensure logging never fails

        Use this method for complex request/response bodies. For simple bodies,
        mask_simple_body() may be sufficient.

        Args:
            body: The request/response body in various formats (str, bytes, dict)

        Returns:
            Masked body as string or bytes (matching input type)

        Example:
            >>> SecurityMasker.mask_complex_body(b'{"users":[{"name":"u","password":"p"}]}')
            b'{"users": [{"name": "u", "password": "******"}]}'
        """
        if not body:
            return body

        original_type = type(body)

        try:
            # Convert to string if bytes
            if isinstance(body, bytes):
                try:
                    body = body.decode("utf-8")
                except UnicodeDecodeError:
                    # If decode fails, return original bytes
                    return body

            # If already a dict, mask and return as JSON string
            if isinstance(body, dict):
                masked_dict = cls._mask_dict_body(body)
                return json.dumps(masked_dict)

            # If string, check if it's JSON
            if isinstance(body, str):
                body = body.strip()
                if body.startswith(("{", "[")):
                    try:
                        # Parse JSON and mask
                        body_json = json.loads(body)
                        masked_json = cls._mask_dict_body(body_json)
                        masked_string = json.dumps(masked_json)

                        # Return in original type
                        if original_type == bytes:
                            return masked_string.encode("utf-8")
                        return masked_string
                    except json.JSONDecodeError:
                        # Not valid JSON, return as-is
                        pass

            # Return body as-is if not JSON or other type
            if original_type == bytes and isinstance(body, str):
                return body.encode("utf-8")
            return body

        except Exception:
            # If anything fails, return original to ensure logging continues
            # Converting to string if needed for logging
            if isinstance(body, bytes):
                try:
                    return body.decode("utf-8", errors="replace")
                except:
                    return "[BODY - BINARY DATA]"
            return body if body else ""

    @classmethod
    def mask_user_input(cls, user_input: str, command_context: Optional[str] = None) -> str:
        """
        Mask sensitive information in user input based on context.

        Args:
            user_input: Raw user input string
            command_context: Optional context about what command is being executed

        Returns:
            User input with sensitive parts masked

        Example:
            >>> SecurityMasker.mask_user_input('--login admin --password MyP@ss')
            '--login admin --password ******'
        """
        if not user_input:
            return user_input

        # Split input into tokens for analysis
        tokens = user_input.split()

        # Apply command argument masking
        masked_tokens = cls.mask_command_arguments(tokens)

        return " ".join(masked_tokens)

    # Private helper methods
    @classmethod
    def _is_sensitive_cli_flag(cls, arg: str) -> bool:
        """Check if an argument is a sensitive command-line flag."""
        return arg.lower() in {flag.lower() for flag in cls.SENSITIVE_CLI_KEYWORDS}

    @classmethod
    def _has_inline_sensitive_value(cls, arg: str) -> bool:
        """Check if an argument contains inline sensitive value (flag=value)."""
        if "=" not in arg:
            return False
        flag = arg.split("=")[0]
        return cls._is_sensitive_cli_flag(flag)

    @classmethod
    def _mask_inline_argument(cls, arg: str) -> str:
        """Mask the value part of an inline argument."""
        return re.sub(r"=(.*)", f"={cls.MASK_VALUE}", arg)

    @classmethod
    def _mask_headers_dict(cls, headers: Dict[str, str]) -> Dict[str, str]:
        """Mask sensitive headers in dictionary format."""
        masked = {}
        for key, value in headers.items():
            if cls._is_sensitive_header(key):
                # Determine if complete or partial masking
                masked[key] = cls._mask_value(value, key, is_header=True)
            else:
                masked[key] = value
        return masked

    @classmethod
    def _mask_headers_list(cls, headers: List[tuple]) -> List[tuple]:
        """Mask sensitive headers in list of tuples format."""
        masked = []
        for item in headers:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                key, value = item[0], item[1]
                if cls._is_sensitive_header(key):
                    masked_value = cls._mask_value(value, key, is_header=True)
                    masked.append((key, masked_value))
                else:
                    masked.append(item)
            else:
                masked.append(item)
        return masked

    @classmethod
    def _mask_headers_string(cls, headers: str) -> str:
        """Mask sensitive headers in string format."""
        lines = headers.split("\n")
        masked_lines = []

        for line in lines:
            if ":" in line:
                key, value = line.split(":", 1)
                if cls._is_sensitive_header(key.strip()):
                    # Preserve leading whitespace (indentation) from original key
                    leading_space = key[: len(key) - len(key.lstrip())]
                    masked_value = cls._mask_value(value.strip(), key.strip(), is_header=True)
                    masked_lines.append(f"{leading_space}{key.strip()}: {masked_value}")
                else:
                    masked_lines.append(line)
            else:
                masked_lines.append(line)

        return "\n".join(masked_lines)

    @classmethod
    def _mask_headers_object(cls, headers: Any) -> str:
        """Mask sensitive headers in object format (e.g., HTTPMessage)."""
        try:
            # Try to convert to dictionary first
            if hasattr(headers, "items"):
                header_dict = dict(headers.items())
                masked_dict = cls._mask_headers_dict(header_dict)
                return str(masked_dict)
            elif hasattr(headers, "__dict__"):
                return cls._mask_headers_dict(headers.__dict__)
            else:
                return "[HEADERS MASKED - UNKNOWN FORMAT]"
        except Exception:
            return "[HEADERS MASKED DUE TO PROCESSING ERROR]"

    @classmethod
    def _is_sensitive_header(cls, header_name: str) -> bool:
        """Check if a header name is considered sensitive."""
        header_lower = header_name.lower().strip()
        return any(sensitive in header_lower for sensitive in cls.SENSITIVE_HEADERS)

    @classmethod
    def _mask_string_body(cls, body: str) -> str:
        """Mask sensitive information in string body."""
        try:
            # Try to parse as JSON
            if body.strip().startswith(("{", "[")):
                json_body = json.loads(body)
                masked_body = cls._mask_dict_body(json_body)
                return json.dumps(masked_body)
            else:
                # Handle form data or other string formats
                return cls._mask_form_data(body)
        except json.JSONDecodeError:
            # Not JSON, treat as form data or plain text
            return cls._mask_form_data(body)

    @classmethod
    def _mask_bytes_body(cls, body: bytes) -> bytes:
        """Mask sensitive information in bytes body."""
        try:
            # Convert to string, mask, then back to bytes
            string_body = body.decode("utf-8")
            masked_string = cls._mask_string_body(string_body)
            return masked_string.encode("utf-8")
        except UnicodeDecodeError:
            # If can't decode, return as-is (likely binary data)
            return body

    @classmethod
    def _mask_dict_body(cls, body: Dict[str, Any]) -> Dict[str, Any]:
        """Mask sensitive information in dictionary body."""
        masked = copy.deepcopy(body)

        def mask_recursive(obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if cls._is_sensitive_body_field(key):
                        # Apply appropriate masking based on field type
                        obj[key] = cls._mask_value(str(value) if value else "", key, is_header=False)
                    else:
                        mask_recursive(value)
            elif isinstance(obj, list):
                for item in obj:
                    mask_recursive(item)

        mask_recursive(masked)
        return masked

    @classmethod
    def _mask_form_data(cls, data: str) -> str:
        """Mask sensitive information in form data."""
        # Handle URL-encoded form data
        if "&" in data and "=" in data:
            pairs = data.split("&")
            masked_pairs = []
            for pair in pairs:
                if "=" in pair:
                    key, value = pair.split("=", 1)
                    if cls._is_sensitive_body_field(key):
                        masked_pairs.append(f"{key}={cls.MASK_VALUE}")
                    else:
                        masked_pairs.append(pair)
                else:
                    masked_pairs.append(pair)
            return "&".join(masked_pairs)

        # For other string formats, return as-is
        return data

    @classmethod
    def _is_sensitive_body_field(cls, field_name: str) -> bool:
        """Check if a body field name is considered sensitive."""
        field_lower = field_name.lower().strip()
        return field_lower in cls.SENSITIVE_BODY_FIELDS

    @classmethod
    def _mask_value(cls, value: str, field_name: str, is_header: bool = False) -> str:
        """
        Mask a sensitive value with either complete or partial masking.

        Args:
            value: The value to mask
            field_name: The field/header name (for determining mask type)
            is_header: Whether this is a header (vs body field)

        Returns:
            Masked value (either completely or partially)
        """
        if not value:
            return cls.MASK_VALUE

        field_lower = field_name.lower().strip()

        # Determine if we should use complete or partial masking
        use_complete_mask = False

        if is_header:
            # Check if header requires complete masking
            use_complete_mask = field_lower in {h.lower() for h in cls.COMPLETE_MASK_HEADERS}
            # Special case: Authorization header with "Basic" is password-based
            if field_lower == "authorization" and value.strip().lower().startswith("basic"):
                use_complete_mask = True
        else:
            # Check if body field requires complete masking
            use_complete_mask = field_lower in {f.lower() for f in cls.COMPLETE_MASK_FIELDS}

        # Apply appropriate masking
        if use_complete_mask:
            return cls.MASK_VALUE
        else:
            # Partial masking: show last N characters
            return cls._partial_mask(value)

    @classmethod
    def _partial_mask(cls, value: str, show_chars: int = None) -> str:
        """
        Apply partial masking to a value, showing only the last N characters.

        Args:
            value: The value to mask
            show_chars: Number of characters to show (default: PARTIAL_MASK_SHOW_CHARS)

        Returns:
            Partially masked value like "******a0fb"
        """
        if show_chars is None:
            show_chars = cls.PARTIAL_MASK_SHOW_CHARS

        if not value or len(value) <= show_chars:
            # If value is too short, completely mask it
            return cls.MASK_VALUE

        # Show last N characters
        visible_part = value[-show_chars:]
        return f"{cls.MASK_VALUE}{visible_part}"


# Convenience functions for backward compatibility and easy usage
def mask_passwords(args: List[str]) -> List[str]:
    """Backward compatible function for masking passwords in command arguments."""
    return SecurityMasker.mask_command_arguments(args)


def mask_http_request_data(method: str, path: str, headers: Any, body: Any) -> tuple:
    """
    Mask all sensitive data in an HTTP request for logging.

    Args:
        method: HTTP method
        path: Request path/URL
        headers: Request headers
        body: Request body

    Returns:
        Tuple of (method, masked_path, masked_headers, masked_body)
    """
    masked_path = SecurityMasker.mask_url_parameters(path)
    masked_headers = SecurityMasker.mask_http_headers(headers)
    masked_body = SecurityMasker.mask_simple_body(body)

    return method, masked_path, masked_headers, masked_body


def mask_user_input(user_input: str, command_context: Optional[str] = None) -> str:
    """Convenience function for masking user input."""
    return SecurityMasker.mask_user_input(user_input, command_context)
