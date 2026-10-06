import math
import re
import string
from typing import Dict, List, Optional
import csv
import json

class TextProcessor:
    """Utility class for text processing operations"""
    
    def __init__(self):
        self.alphabet = string.ascii_uppercase
    
    def process_text(self, text: str, 
                    remove_spaces: bool = False,
                    remove_punctuation: bool = False,
                    to_uppercase: bool = False,
                    remove_numbers: bool = False,
                    keep_only_letters: bool = False) -> str:
        """Process text according to specified options"""
        
        # Input validation - limit text length for security
        if len(text) > 50000:
            raise ValueError("Text too long. Maximum 50,000 characters allowed.")
        
        processed = text
        
        if to_uppercase:
            processed = processed.upper()
        
        if remove_numbers:
            processed = re.sub(r'\d', '', processed)
        
        if remove_punctuation:
            processed = re.sub(r'[^\w\s]', '', processed)
        
        if remove_spaces:
            processed = re.sub(r'\s', '', processed)
        
        if keep_only_letters:
            processed = re.sub(r'[^A-Za-z]', '', processed)
        
        return processed
    
    def clean_for_cipher(self, text: str) -> str:
        """Clean text for cipher operations (letters only, uppercase)"""
        return ''.join(c.upper() for c in text if c.isalpha())
    
    def format_output(self, text: str, group_size: int = 5) -> str:
        """Format text output in groups for readability"""
        if group_size <= 0:
            return text
        
        formatted = ""
        for i in range(0, len(text), group_size):
            if i > 0:
                formatted += " "
            formatted += text[i:i + group_size]
        
        return formatted
    
    def extract_words(self, text: str, min_length: int = 1) -> List[str]:
        """Extract words from text with minimum length filter"""
        words = re.findall(r'[A-Za-z]+', text)
        return [word.upper() for word in words if len(word) >= min_length]
    
    def count_characters(self, text: str, char_type: str = 'all') -> int:
        """Count characters of specified type"""
        if char_type == 'letters':
            return sum(1 for c in text if c.isalpha())
        elif char_type == 'digits':
            return sum(1 for c in text if c.isdigit())
        elif char_type == 'spaces':
            return sum(1 for c in text if c.isspace())
        elif char_type == 'punctuation':
            return sum(1 for c in text if c in string.punctuation)
        else:  # 'all'
            return len(text)
    
    def normalize_text(self, text: str) -> str:
        """Normalize text for consistent processing"""
        # Remove extra whitespace and normalize case
        normalized = re.sub(r'\s+', ' ', text.strip())
        return normalized

class FileHandler:
    """Utility class for file operations"""
    
    @staticmethod
    def read_text_file(file_path: str) -> str:
        """Read text from file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                return file.read()
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {file_path}")
        except Exception as e:
            raise Exception(f"Error reading file: {str(e)}")
    
    @staticmethod
    def write_text_file(file_path: str, content: str):
        """Write text to file"""
        try:
            with open(file_path, 'w', encoding='utf-8') as file:
                file.write(content)
        except Exception as e:
            raise Exception(f"Error writing file: {str(e)}")
    
    @staticmethod
    def export_results_txt(results: Dict, file_path: str):
        """Export decryption results to text file"""
        try:
            with open(file_path, 'w', encoding='utf-8') as file:
                file.write("Cryptographic Analysis Results\n")
                file.write("=" * 50 + "\n\n")
                
                for key, value in results.items():
                    file.write(f"{key}:\n")
                    if isinstance(value, dict):
                        for sub_key, sub_value in value.items():
                            file.write(f"  {sub_key}: {sub_value}\n")
                    elif isinstance(value, list):
                        for item in value:
                            file.write(f"  - {item}\n")
                    else:
                        file.write(f"  {value}\n")
                    file.write("\n")
        except Exception as e:
            raise Exception(f"Error exporting results: {str(e)}")
    
    @staticmethod
    def export_results_csv(results: Dict, file_path: str):
        """Export decryption results to CSV file"""
        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow(['Category', 'Key', 'Value'])
                
                for category, data in results.items():
                    if isinstance(data, dict):
                        for key, value in data.items():
                            writer.writerow([category, key, str(value)])
                    elif isinstance(data, list):
                        for i, item in enumerate(data):
                            writer.writerow([category, f"Item_{i+1}", str(item)])
                    else:
                        writer.writerow([category, 'Value', str(data)])
        except Exception as e:
            raise Exception(f"Error exporting to CSV: {str(e)}")
    
    @staticmethod
    def export_results_json(results: Dict, file_path: str):
        """Export decryption results to JSON file"""
        try:
            with open(file_path, 'w', encoding='utf-8') as file:
                json.dump(results, file, indent=2, ensure_ascii=False)
        except Exception as e:
            raise Exception(f"Error exporting to JSON: {str(e)}")

class CipherValidator:
    """Utility class for validating cipher inputs and outputs"""
    
    @staticmethod
    def validate_caesar_shift(shift: int) -> bool:
        """Validate Caesar cipher shift value"""
        return 0 <= shift <= 25
    
    @staticmethod
    def validate_vigenere_key(key: str) -> bool:
        """Validate Vigenère cipher key"""
        if not key:
            return False
        return all(c.isalpha() for c in key)
    
    @staticmethod
    def validate_substitution_key(key: str) -> bool:
        """Validate substitution cipher key"""
        if len(key) != 26:
            return False
        
        # Check if all characters are unique and alphabetic
        key_upper = key.upper()
        return (len(set(key_upper)) == 26 and 
                all(c in string.ascii_uppercase for c in key_upper))
    
    @staticmethod
    def validate_text_input(text: str, min_length: int = 1) -> bool:
        """Validate text input"""
        if not text or len(text.strip()) < min_length:
            return False
        return True
    
    @staticmethod
    def get_validation_message(validation_type: str, is_valid: bool, details: str = "") -> str:
        """Get appropriate validation message"""
        messages = {
            'caesar_shift': {
                True: "Valid Caesar shift (0-25)",
                False: "Invalid Caesar shift. Must be between 0 and 25."
            },
            'vigenere_key': {
                True: "Valid Vigenère key",
                False: "Invalid Vigenère key. Must contain only letters."
            },
            'substitution_key': {
                True: "Valid substitution key",
                False: "Invalid substitution key. Must be 26 unique letters."
            },
            'text_input': {
                True: "Valid text input",
                False: "Invalid text input. Text is too short or empty."
            }
        }
        
        base_message = messages.get(validation_type, {}).get(is_valid, "Unknown validation result")
        
        if details and not is_valid:
            return f"{base_message} {details}"
        
        return base_message

class StatisticalHelpers:
    """Helper functions for statistical analysis"""
    
    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in text.upper():
            if char.isalpha():
                char_counts[char] = char_counts.get(char, 0) + 1
        
        if not char_counts:
            return 0.0
        
        # Calculate entropy
        total_chars = sum(char_counts.values())
        entropy = 0.0
        
        for count in char_counts.values():
            probability = count / total_chars
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def calculate_coincidence_index(text: str) -> float:
        """Calculate Index of Coincidence"""
        text = ''.join(c.upper() for c in text if c.isalpha())
        n = len(text)
        
        if n < 2:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate IC
        ic = sum(count * (count - 1) for count in char_counts.values()) / (n * (n - 1))
        return ic
    
    @staticmethod
    def chi_squared_goodness_of_fit(observed: List[int], expected: List[float]) -> float:
        """Calculate chi-squared statistic for goodness of fit test"""
        if len(observed) != len(expected):
            raise ValueError("Observed and expected lists must have same length")
        
        chi_squared = 0.0
        for obs, exp in zip(observed, expected):
            if exp > 0:
                chi_squared += ((obs - exp) ** 2) / exp
        
        return chi_squared
    
    @staticmethod
    def normalize_frequencies(frequencies: Dict[str, int]) -> Dict[str, float]:
        """Normalize frequency counts to percentages"""
        total = sum(frequencies.values())
        if total == 0:
            return {}
        
        return {char: (count / total) * 100 for char, count in frequencies.items()}

class PatternMatcher:
    """Utility class for pattern matching operations"""
    
    def __init__(self):
        self.common_english_patterns = {
            'double_letters': ['LL', 'SS', 'EE', 'OO', 'TT', 'FF', 'RR', 'NN'],
            'common_trigrams': ['THE', 'AND', 'ING', 'HER', 'HAT', 'HIS', 'THA', 'ERE', 'FOR', 'ENT'],
            'common_endings': ['ING', 'ION', 'TED', 'ER ', 'LY ', 'AL ', 'TH ', 'IC '],
            'common_beginnings': [' TH', ' AN', ' IN', ' TO', ' A ', ' BE', ' OF', ' AT', ' BY', ' FO']
        }
    
    def find_pattern_matches(self, text: str, pattern_type: str) -> List[tuple]:
        """Find matches for specific pattern types"""
        text = text.upper()
        matches = []
        
        if pattern_type in self.common_english_patterns:
            patterns = self.common_english_patterns[pattern_type]
            
            for pattern in patterns:
                start = 0
                while True:
                    pos = text.find(pattern, start)
                    if pos == -1:
                        break
                    matches.append((pattern, pos))
                    start = pos + 1
        
        return matches
    
    def analyze_word_structure(self, word: str) -> Dict[str, any]:
        """Analyze the structure of a word for pattern matching"""
        word = word.upper()
        
        analysis = {
            'length': len(word),
            'unique_chars': len(set(word)),
            'repeated_chars': [],
            'pattern': '',
            'vowel_positions': [],
            'consonant_positions': []
        }
        
        # Find repeated characters
        char_positions = {}
        for i, char in enumerate(word):
            if char not in char_positions:
                char_positions[char] = []
            char_positions[char].append(i)
        
        analysis['repeated_chars'] = {char: positions for char, positions in char_positions.items() if len(positions) > 1}
        
        # Create pattern string
        char_map = {}
        pattern_num = 1
        pattern = ""
        
        for char in word:
            if char not in char_map:
                char_map[char] = str(pattern_num)
                pattern_num += 1
            pattern += char_map[char]
        
        analysis['pattern'] = pattern
        
        # Find vowel and consonant positions
        vowels = 'AEIOU'
        for i, char in enumerate(word):
            if char in vowels:
                analysis['vowel_positions'].append(i)
            else:
                analysis['consonant_positions'].append(i)
        
        return analysis
