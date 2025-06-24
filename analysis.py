from collections import Counter, defaultdict
import re
import string
import math

class FrequencyAnalysis:
    """Class for performing frequency analysis on ciphertext"""
    
    def __init__(self):
        self.alphabet = string.ascii_uppercase
        self.english_frequencies = {
            'A': 8.12, 'B': 1.49, 'C': 2.78, 'D': 4.25, 'E': 12.02, 'F': 2.23,
            'G': 2.02, 'H': 6.09, 'I': 6.97, 'J': 0.15, 'K': 0.77, 'L': 4.03,
            'M': 2.41, 'N': 6.75, 'O': 7.51, 'P': 1.93, 'Q': 0.10, 'R': 5.99,
            'S': 6.33, 'T': 9.06, 'U': 2.76, 'V': 0.98, 'W': 2.36, 'X': 0.15,
            'Y': 1.97, 'Z': 0.07
        }
        
        self.common_bigrams = [
            'TH', 'HE', 'IN', 'ER', 'AN', 'RE', 'ED', 'ND', 'ON', 'EN',
            'AT', 'OU', 'EA', 'HA', 'NG', 'AS', 'OR', 'TI', 'IS', 'ET'
        ]
        
        self.common_trigrams = [
            'THE', 'AND', 'ING', 'HER', 'HAT', 'HIS', 'THA', 'ERE', 'FOR', 'ENT',
            'ION', 'TER', 'WAS', 'YOU', 'ITH', 'VER', 'ALL', 'WIT', 'THI', 'TIO'
        ]
    
    def character_frequency(self, text):
        """Calculate frequency of each character in the text"""
        text = ''.join(c.upper() for c in text if c.isalpha())
        return Counter(text)
    
    def character_frequency_percentage(self, text):
        """Calculate frequency percentage of each character"""
        freq = self.character_frequency(text)
        total = sum(freq.values())
        
        if total == 0:
            return {}
        
        percentages = {}
        for char, count in freq.items():
            percentages[char] = (count / total) * 100
        
        return percentages
    
    def bigram_frequency(self, text):
        """Calculate frequency of bigrams (2-character sequences)"""
        text = ''.join(c.upper() for c in text if c.isalpha())
        bigrams = []
        
        for i in range(len(text) - 1):
            bigrams.append(text[i:i+2])
        
        return Counter(bigrams)
    
    def trigram_frequency(self, text):
        """Calculate frequency of trigrams (3-character sequences)"""
        text = ''.join(c.upper() for c in text if c.isalpha())
        trigrams = []
        
        for i in range(len(text) - 2):
            trigrams.append(text[i:i+3])
        
        return Counter(trigrams)
    
    def english_frequency_order(self):
        """Return English letters in order of frequency"""
        return "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    
    def compare_with_english(self, text):
        """Compare text frequency with English frequency"""
        text_freq = self.character_frequency_percentage(text)
        
        comparison = {}
        for char in self.alphabet:
            text_pct = text_freq.get(char, 0)
            english_pct = self.english_frequencies.get(char, 0)
            difference = abs(text_pct - english_pct)
            comparison[char] = {
                'text_freq': text_pct,
                'english_freq': english_pct,
                'difference': difference
            }
        
        return comparison
    
    def chi_squared_test(self, text):
        """Perform chi-squared test against English frequency"""
        text_freq = self.character_frequency(text)
        total_chars = sum(text_freq.values())
        
        if total_chars == 0:
            return float('inf')
        
        chi_squared = 0
        for char in self.alphabet:
            observed = text_freq.get(char, 0)
            expected = (self.english_frequencies[char] / 100) * total_chars
            
            if expected > 0:
                chi_squared += ((observed - expected) ** 2) / expected
        
        return chi_squared
    
    def index_of_coincidence(self, text):
        """Calculate Index of Coincidence"""
        text = ''.join(c.upper() for c in text if c.isalpha())
        n = len(text)
        
        if n < 2:
            return 0
        
        freq = Counter(text)
        ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
        return ic
    
    def mutual_index_of_coincidence(self, text1, text2):
        """Calculate mutual index of coincidence between two texts"""
        text1 = ''.join(c.upper() for c in text1 if c.isalpha())
        text2 = ''.join(c.upper() for c in text2 if c.isalpha())
        
        n1, n2 = len(text1), len(text2)
        if n1 == 0 or n2 == 0:
            return 0
        
        freq1 = Counter(text1)
        freq2 = Counter(text2)
        
        mic = 0
        for char in self.alphabet:
            mic += freq1.get(char, 0) * freq2.get(char, 0)
        
        return mic / (n1 * n2)

class PatternAnalysis:
    """Class for analyzing patterns in ciphertext"""
    
    def __init__(self):
        self.alphabet = string.ascii_uppercase
    
    def find_repeated_sequences(self, text, min_length=3):
        """Find repeated sequences of characters"""
        text = ''.join(c.upper() for c in text if c.isalpha())
        repeated = defaultdict(list)
        
        # Find all substrings of minimum length or greater
        for length in range(min_length, min(len(text) // 2 + 1, 20)):  # Limit search to reasonable lengths
            for i in range(len(text) - length + 1):
                substring = text[i:i+length]
                
                # Look for this substring in the rest of the text
                for j in range(i + length, len(text) - length + 1):
                    if text[j:j+length] == substring:
                        if substring not in repeated or i not in repeated[substring]:
                            repeated[substring].append(i)
                        if j not in repeated[substring]:
                            repeated[substring].append(j)
        
        # Filter out sequences that appear only once
        repeated = {seq: positions for seq, positions in repeated.items() if len(positions) > 1}
        
        # Sort positions for each sequence
        for seq in repeated:
            repeated[seq].sort()
        
        return dict(repeated)
    
    def kasiski_examination(self, text, min_length=3):
        """Perform Kasiski examination to find probable key lengths"""
        repeated = self.find_repeated_sequences(text, min_length)
        
        all_distances = []
        distance_info = {}
        
        for seq, positions in repeated.items():
            distances = []
            for i in range(len(positions) - 1):
                distance = positions[i + 1] - positions[i]
                distances.append(distance)
                all_distances.append(distance)
            
            distance_info[seq] = distances
        
        # Find GCD of all distances to suggest key lengths
        if all_distances:
            key_length_candidates = self._find_common_factors(all_distances)
        else:
            key_length_candidates = {}
        
        return {
            'repeated_sequences': repeated,
            'distances': distance_info,
            'key_length_candidates': key_length_candidates
        }
    
    def _find_common_factors(self, numbers):
        """Find common factors among a list of numbers"""
        if not numbers:
            return {}
        
        # Count how often each factor appears
        factor_count = defaultdict(int)
        
        for num in numbers:
            factors = self._get_factors(num)
            for factor in factors:
                if factor > 1:  # Ignore factor of 1
                    factor_count[factor] += 1
        
        return dict(factor_count)
    
    def _get_factors(self, n):
        """Get all factors of a number"""
        factors = []
        for i in range(1, int(math.sqrt(n)) + 1):
            if n % i == 0:
                factors.append(i)
                if i != n // i:
                    factors.append(n // i)
        return factors
    
    def analyze_word_patterns(self, text):
        """Analyze patterns in words (useful for substitution ciphers)"""
        # Remove non-alphabetic characters and split into words
        text = re.sub(r'[^A-Za-z\s]', '', text).upper()
        words = text.split()
        
        patterns = defaultdict(list)
        
        for word in words:
            if len(word) > 1:  # Skip single letters
                pattern = self._get_word_pattern(word)
                patterns[pattern].append(word)
        
        # Only return patterns that appear multiple times
        return {pattern: word_list for pattern, word_list in patterns.items() if len(word_list) > 1}
    
    def _get_word_pattern(self, word):
        """Convert word to pattern (e.g., 'HELLO' -> '12334')"""
        char_map = {}
        pattern = ""
        next_num = 1
        
        for char in word:
            if char not in char_map:
                char_map[char] = str(next_num)
                next_num += 1
            pattern += char_map[char]
        
        return pattern
    
    def character_positions(self, text, target_char):
        """Find all positions of a specific character"""
        text = text.upper()
        target_char = target_char.upper()
        
        positions = []
        for i, char in enumerate(text):
            if char == target_char:
                positions.append(i)
        
        return positions
    
    def analyze_position_patterns(self, text, target_char):
        """Analyze patterns in character positions"""
        positions = self.character_positions(text, target_char)
        
        if len(positions) < 2:
            return {"positions": positions, "analysis": "Not enough occurrences for pattern analysis"}
        
        # Calculate differences between consecutive positions
        differences = []
        for i in range(len(positions) - 1):
            differences.append(positions[i + 1] - positions[i])
        
        analysis = {
            "positions": positions,
            "differences": differences,
            "average_distance": sum(differences) / len(differences) if differences else 0,
            "min_distance": min(differences) if differences else 0,
            "max_distance": max(differences) if differences else 0
        }
        
        # Check for regular patterns
        if len(set(differences)) == 1:
            analysis["pattern_type"] = "Regular interval"
            analysis["interval"] = differences[0]
        elif len(set(differences)) <= 3:
            analysis["pattern_type"] = "Semi-regular pattern"
            analysis["common_intervals"] = Counter(differences)
        else:
            analysis["pattern_type"] = "Irregular pattern"
        
        return analysis
    
    def find_probable_words(self, text, word_length=None):
        """Find probable words based on common English patterns"""
        text = re.sub(r'[^A-Za-z\s]', '', text).upper()
        words = text.split()
        
        probable_words = {
            1: ['A', 'I'],
            2: ['OF', 'TO', 'IN', 'IT', 'IS', 'BE', 'AS', 'AT', 'SO', 'WE', 'HE', 'BY', 'OR', 'ON', 'DO', 'IF', 'ME', 'MY', 'UP', 'AN', 'GO', 'NO', 'US', 'AM'],
            3: ['THE', 'AND', 'FOR', 'ARE', 'BUT', 'NOT', 'YOU', 'ALL', 'CAN', 'HER', 'WAS', 'ONE', 'OUR', 'OUT', 'DAY', 'GET', 'HAS', 'HIM', 'HIS', 'HOW', 'ITS', 'MAY', 'NEW', 'NOW', 'OLD', 'SEE', 'TWO', 'WHO', 'BOY', 'DID', 'HAD', 'LET', 'MAN', 'PUT', 'SAY', 'SHE', 'TOO', 'USE']
        }
        
        results = {}
        
        for word in words:
            length = len(word)
            if word_length is None or length == word_length:
                if length in probable_words:
                    results[word] = probable_words[length]
                else:
                    results[word] = ["Unknown pattern"]
        
        return results
