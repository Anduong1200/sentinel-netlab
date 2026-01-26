class SecurityAnalyzer:
    @staticmethod
    def analyze_network(ssid, encryption, rssi):
        """
        Analyze network security and return risk assessment.
        Returns: (risk_level, risk_color, description)
        """
        risk_level = "LOW"
        risk_color = "green"
        description = "Secure"

        # Check Encryption
        # Normalize encryption string
        enc_upper = str(encryption).upper()
        
        if "OPEN" in enc_upper:
            risk_level = "HIGH"
            risk_color = "red"
            description = "No Encryption (Open Network)"
        elif "WEP" in enc_upper:
            risk_level = "HIGH"
            risk_color = "red"
            description = "Weak Encryption (WEP is broken)"
        elif "WPA" in enc_upper and "WPA2" not in enc_upper and "WPA3" not in enc_upper:
             # Just WPA (TKIP)
            risk_level = "MEDIUM"
            risk_color = "orange"
            description = "Legacy Encryption (WPA1)"
        elif "WPA2" in enc_upper or "WPA3" in enc_upper:
            risk_level = "LOW"
            risk_color = "green" 
            description = "Strong Encryption"
        else:
            # Unknown
            risk_level = "MEDIUM"
            risk_color = "yellow"
            description = "Unknown Security"

        # Signal Strength Context (Just for info, doesnt change risk typically, 
        # but could imply 'Evil Twin' if very strong signal for a known public net)
        
        return {
            "level": risk_level,
            "color": risk_color,
            "desc": description
        }

    @staticmethod
    def get_signal_quality(rssi):
        if rssi >= -50: return "Excellent"
        if rssi >= -60: return "Good"
        if rssi >= -70: return "Fair"
        return "Weak"
