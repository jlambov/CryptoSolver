import string
from collections import Counter
import math

class CaesarCipher:
    """Implementation of Caesar cipher encryption and decryption"""
    
    def __init__(self):
        self.alphabet = string.ascii_uppercase
    
    def encrypt(self, text, shift):
        """Encrypt text using Caesar cipher with given shift"""
        result = ""
        for char in text.upper():
            if char in self.alphabet:
                old_index = self.alphabet.index(char)
                new_index = (old_index + shift) % 26
                result += self.alphabet[new_index]
            else:
                result += char
        return result
    
    def decrypt(self, text, shift):
        """Decrypt text using Caesar cipher with given shift"""
        return self.encrypt(text, -shift)
    
    def brute_force_decrypt(self, text):
        """Try all possible shifts and return results"""
        results = {}
        for shift in range(26):
            results[shift] = self.decrypt(text, shift)
        return results

class VigenereCipher:
    """Implementation of Vigenère cipher encryption and decryption"""
    
    def __init__(self):
        self.alphabet = string.ascii_uppercase
    
    def encrypt(self, text, key):
        """Encrypt text using Vigenère cipher with given key"""
        if not key:
            raise ValueError("Key cannot be empty")
        
        key = key.upper()
        text = text.upper()
        result = ""
        key_index = 0
        
        for char in text:
            if char in self.alphabet:
                # Get the shift from the key
                shift = self.alphabet.index(key[key_index % len(key)])
                # Apply Caesar cipher with this shift
                old_index = self.alphabet.index(char)
                new_index = (old_index + shift) % 26
                result += self.alphabet[new_index]
                key_index += 1
            else:
                result += char
        
        return result
    
    def decrypt(self, text, key):
        """Decrypt text using Vigenère cipher with given key"""
        if not key:
            raise ValueError("Key cannot be empty")
        
        key = key.upper()
        text = text.upper()
        result = ""
        key_index = 0
        
        for char in text:
            if char in self.alphabet:
                # Get the shift from the key
                shift = self.alphabet.index(key[key_index % len(key)])
                # Apply Caesar cipher with negative shift
                old_index = self.alphabet.index(char)
                new_index = (old_index - shift) % 26
                result += self.alphabet[new_index]
                key_index += 1
            else:
                result += char
        
        return result
    
    def analyze_key_length(self, text, max_key_length=20):
        """Analyze probable key lengths using Index of Coincidence"""
        text = ''.join(c.upper() for c in text if c.isalpha())
        key_length_scores = {}
        
        for key_length in range(2, min(max_key_length + 1, len(text) // 2)):
            # Divide text into columns based on key length
            columns = [''] * key_length
            for i, char in enumerate(text):
                columns[i % key_length] += char
            
            # Calculate average IC for all columns
            total_ic = 0
            for column in columns:
                if len(column) > 1:
                    total_ic += self._calculate_ic(column)
            
            avg_ic = total_ic / key_length if key_length > 0 else 0
            key_length_scores[key_length] = avg_ic
        
        return key_length_scores
    
    def _calculate_ic(self, text):
        """Calculate Index of Coincidence for text"""
        n = len(text)
        if n < 2:
            return 0
        
        freq = Counter(text)
        ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
        return ic
    
    def attempt_key_recovery(self, text, key_length):
        """Attempt to recover the key for a given key length"""
        text = ''.join(c.upper() for c in text if c.isalpha())
        
        # Divide text into columns
        columns = [''] * key_length
        for i, char in enumerate(text):
            columns[i % key_length] += char
        
        # For each column, find the most likely Caesar shift
        key = ""
        for column in columns:
            if column:
                best_shift = self._find_best_caesar_shift(column)
                key += self.alphabet[best_shift]
            else:
                key += 'A'  # Default if column is empty
        
        return key
    
    def _find_best_caesar_shift(self, text):
        """Find the most likely Caesar shift for a column of text"""
        english_freq = {
            'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7, 'S': 6.3, 'H': 6.1,
            'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8, 'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2,
            'G': 2.0, 'Y': 2.0, 'P': 1.9, 'B': 1.3, 'V': 1.0, 'K': 0.8, 'J': 0.15, 'X': 0.15,
            'Q': 0.10, 'Z': 0.07
        }
        
        best_shift = 0
        best_score = 0
        
        for shift in range(26):
            # Decrypt with this shift
            decrypted = ""
            for char in text:
                old_index = self.alphabet.index(char)
                new_index = (old_index - shift) % 26
                decrypted += self.alphabet[new_index]
            
            # Score based on English frequency
            score = 0
            for char in decrypted:
                score += english_freq.get(char, 0)
            
            if score > best_score:
                best_score = score
                best_shift = shift
        
        return best_shift

class SubstitutionCipher:
    """Implementation of monoalphabetic substitution cipher"""
    
    def __init__(self):
        self.alphabet = string.ascii_uppercase
        self.english_freq_order = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    
    def encrypt(self, text, key):
        """Encrypt text using substitution cipher with given key mapping"""
        if len(key) != 26:
            raise ValueError("Key must be exactly 26 characters long")
        
        result = ""
        for char in text.upper():
            if char in self.alphabet:
                old_index = self.alphabet.index(char)
                result += key[old_index].upper()
            else:
                result += char
        return result
    
    def decrypt(self, text, key):
        """Decrypt text using substitution cipher with given key mapping"""
        if len(key) != 26:
            raise ValueError("Key must be exactly 26 characters long")
        
        # Create reverse mapping
        reverse_key = [''] * 26
        for i, char in enumerate(key.upper()):
            if char in self.alphabet:
                reverse_key[self.alphabet.index(char)] = self.alphabet[i]
        
        result = ""
        for char in text.upper():
            if char in self.alphabet:
                old_index = self.alphabet.index(char)
                if reverse_key[old_index]:
                    result += reverse_key[old_index]
                else:
                    result += char  # Unknown mapping
            else:
                result += char
        return result
    
    def decrypt_with_mapping(self, text, partial_mapping):
        """Decrypt text using a partial character mapping"""
        result = ""
        for char in text.upper():
            if char in partial_mapping:
                result += partial_mapping[char]
            else:
                result += char
        return result
    
    def suggest_mappings(self, text):
        """Suggest character mappings based on frequency analysis"""
        text = ''.join(c.upper() for c in text if c.isalpha())
        
        # Get frequency of characters in ciphertext
        freq = Counter(text)
        cipher_freq_order = [char for char, count in freq.most_common()]
        
        # Map most frequent cipher chars to most frequent English chars
        suggestions = {}
        for i, cipher_char in enumerate(cipher_freq_order):
            if i < len(self.english_freq_order):
                suggestions[cipher_char] = self.english_freq_order[i]
        
        return suggestions
    
    def analyze_patterns(self, text):
        """Analyze common patterns in the ciphertext"""
        text = ''.join(c.upper() for c in text if c.isalpha())
        
        patterns = {
            'double_letters': [],
            'single_char_words': [],
            'three_char_words': [],
            'common_endings': []
        }
        
        words = text.split()
        
        for word in words:
            # Find double letters
            for i in range(len(word) - 1):
                if word[i] == word[i + 1]:
                    patterns['double_letters'].append(word[i] + word[i])
            
            # Find single character words (likely A or I)
            if len(word) == 1:
                patterns['single_char_words'].append(word)
            
            # Find three character words (could be THE, AND, etc.)
            if len(word) == 3:
                patterns['three_char_words'].append(word)
            
            # Find common endings
            if len(word) > 2:
                ending = word[-3:]
                patterns['common_endings'].append(ending)
        
        # Count occurrences
        for key in patterns:
            patterns[key] = Counter(patterns[key])
        
        return patterns
    
    def get_pattern_suggestions(self, patterns):
        """Get suggestions based on common patterns"""
        suggestions = {}
        
        # Single character words are likely A or I
        if patterns['single_char_words']:
            most_common_single = patterns['single_char_words'].most_common(1)[0][0]
            suggestions[most_common_single] = 'A'  # Most likely A
        
        # Three character words - THE is most common
        if patterns['three_char_words']:
            most_common_three = patterns['three_char_words'].most_common(1)[0][0]
            if most_common_three not in ''.join(suggestions.keys()):
                # Suggest this is THE
                suggestions[most_common_three[0]] = 'T'
                suggestions[most_common_three[1]] = 'H'
                suggestions[most_common_three[2]] = 'E'
        
        return suggestions
