"""
Kryptos Cipher Analysis Module

This module contains specialized tools for analyzing the Kryptos sculpture cipher,
including the unsolved K4 section. It includes implementations for the known
techniques used in K1-K3 and advanced analysis for K4.
"""

import string
import re
from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Optional
import itertools
import math

class KryptosCipher:
    """Implementation of Kryptos cipher analysis and decryption methods"""
    
    def __init__(self):
        self.alphabet = "KRYPTOSABCDEFGHIJLMNQUVWXZ"  # Kryptos alphabet
        self.standard_alphabet = string.ascii_uppercase
        
        # Known Kryptos sections (K1, K2, K3 are solved)
        self.k1_plaintext = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
        self.k2_plaintext = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLE?THEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHIS?THEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWSTHEEXACTLOCATION?ONLYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFRTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGRESEIGHTMINUTESFORTYFOURSECONDSWESTXLAYERTWO"
        self.k3_plaintext = "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEATINYBREACHINTHEUPPERLEFTHANDCORNERANDTHENWIDENINGTHEHOLEALITTLEIINSERTEDTHECANDLEANDPEERINGINTHEHOTAIRESCAPINGFROMTHECHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILSOFTHEROOMWITHINEMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ?"
        
        # K4 ciphertext (unsolved) - 97 characters
        self.k4_ciphertext = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
        
        # Known plaintext positions in K4
        self.k4_known_positions = {
            # EASTNORTHEAST at positions 22-34 (0-indexed: 21-33)
            21: 'E', 22: 'A', 23: 'S', 24: 'T', 25: 'N', 26: 'O', 27: 'R', 28: 'T', 29: 'H', 30: 'E', 31: 'A', 32: 'S', 33: 'T',
            # BERLIN at positions 64-69 (0-indexed: 63-68)
            63: 'B', 64: 'E', 65: 'R', 66: 'L', 67: 'I', 68: 'N',
            # CLOCK at positions 70-74 (0-indexed: 69-73)
            69: 'C', 70: 'L', 71: 'O', 72: 'C', 73: 'K'
        }
    
    def analyze_k4_with_known_plaintext(self):
        """Analyze K4 using the known plaintext segments"""
        analysis = {
            'ciphertext': self.k4_ciphertext,
            'length': len(self.k4_ciphertext),
            'known_positions': self.k4_known_positions,
            'known_mappings': {},
            'possible_key_patterns': [],
            'analysis_results': {}
        }
        
        # Extract cipher-plaintext mappings from known positions
        for pos, plain_char in self.k4_known_positions.items():
            if pos < len(self.k4_ciphertext):
                cipher_char = self.k4_ciphertext[pos]
                if cipher_char not in analysis['known_mappings']:
                    analysis['known_mappings'][cipher_char] = []
                analysis['known_mappings'][cipher_char].append((plain_char, pos))
        
        return analysis
    
    def vigenere_analysis_k4(self, potential_key_length: int = None):
        """Perform Vigenère analysis on K4 with known plaintext"""
        results = {}
        
        # If no key length specified, try common lengths
        key_lengths = [potential_key_length] if potential_key_length else range(2, 21)
        
        for key_len in key_lengths:
            key_analysis = self._analyze_key_length_k4(key_len)
            if key_analysis['confidence'] > 0:
                results[key_len] = key_analysis
        
        return results
    
    def _analyze_key_length_k4(self, key_length: int):
        """Analyze specific key length for K4 using known plaintext"""
        analysis = {
            'key_length': key_length,
            'partial_key': ['?'] * key_length,
            'confidence': 0,
            'key_positions_found': 0,
            'conflicts': []
        }
        
        # Use known plaintext to determine key characters
        for pos, plain_char in self.k4_known_positions.items():
            if pos < len(self.k4_ciphertext):
                cipher_char = self.k4_ciphertext[pos]
                key_pos = pos % key_length
                
                # Calculate what the key character should be
                if cipher_char in self.alphabet and plain_char in self.standard_alphabet:
                    cipher_idx = self.alphabet.index(cipher_char)
                    plain_idx = self.standard_alphabet.index(plain_char)
                    
                    # For Vigenère: cipher = (plain + key) mod 26
                    # So: key = (cipher - plain) mod 26
                    key_idx = (cipher_idx - plain_idx) % len(self.alphabet)
                    key_char = self.alphabet[key_idx]
                    
                    if analysis['partial_key'][key_pos] == '?':
                        analysis['partial_key'][key_pos] = key_char
                        analysis['key_positions_found'] += 1
                    elif analysis['partial_key'][key_pos] != key_char:
                        analysis['conflicts'].append({
                            'position': key_pos,
                            'existing': analysis['partial_key'][key_pos],
                            'new': key_char,
                            'cipher_pos': pos
                        })
        
        # Calculate confidence based on consistency and coverage
        if len(analysis['conflicts']) == 0 and analysis['key_positions_found'] > 0:
            analysis['confidence'] = analysis['key_positions_found'] / key_length
        else:
            analysis['confidence'] = max(0, analysis['key_positions_found'] - len(analysis['conflicts'])) / key_length
        
        return analysis
    
    def attempt_k4_decryption(self, key: str):
        """Attempt to decrypt K4 with a given key"""
        if not key:
            return None
        
        key = key.upper()
        result = ""
        
        for i, cipher_char in enumerate(self.k4_ciphertext):
            if cipher_char in self.alphabet:
                key_char = key[i % len(key)]
                if key_char in self.alphabet:
                    cipher_idx = self.alphabet.index(cipher_char)
                    key_idx = self.alphabet.index(key_char)
                    
                    # Vigenère decryption: plain = (cipher - key) mod alphabet_size
                    plain_idx = (cipher_idx - key_idx) % len(self.alphabet)
                    
                    # Map back to standard alphabet
                    if plain_idx < len(self.standard_alphabet):
                        result += self.standard_alphabet[plain_idx]
                    else:
                        result += '?'
                else:
                    result += cipher_char
            else:
                result += cipher_char
        
        return result
    
    def verify_decryption(self, decrypted_text: str):
        """Verify if decrypted text matches known plaintext segments"""
        matches = 0
        total_known = len(self.k4_known_positions)
        
        verification = {
            'matches': 0,
            'total_known': total_known,
            'accuracy': 0.0,
            'mismatches': []
        }
        
        for pos, expected_char in self.k4_known_positions.items():
            if pos < len(decrypted_text):
                actual_char = decrypted_text[pos]
                if actual_char == expected_char:
                    matches += 1
                else:
                    verification['mismatches'].append({
                        'position': pos,
                        'expected': expected_char,
                        'actual': actual_char
                    })
        
        verification['matches'] = matches
        verification['accuracy'] = matches / total_known if total_known > 0 else 0
        
        return verification
    
    def brute_force_partial_key(self, known_key_positions: Dict[int, str], max_unknown: int = 3):
        """Brute force unknown positions in a partially known key"""
        if not known_key_positions:
            return []
        
        # Determine key length from known positions
        key_length = max(known_key_positions.keys()) + 1
        
        # Find unknown positions
        unknown_positions = [i for i in range(key_length) if i not in known_key_positions]
        
        if len(unknown_positions) > max_unknown:
            return []  # Too many unknowns for brute force
        
        results = []
        
        # Generate all possible combinations for unknown positions
        for combination in itertools.product(self.alphabet, repeat=len(unknown_positions)):
            # Create full key
            full_key = ['?'] * key_length
            
            # Fill known positions
            for pos, char in known_key_positions.items():
                full_key[pos] = char
            
            # Fill unknown positions with current combination
            for i, char in enumerate(combination):
                full_key[unknown_positions[i]] = char
            
            key_string = ''.join(full_key)
            
            # Test this key
            decrypted = self.attempt_k4_decryption(key_string)
            if decrypted:
                verification = self.verify_decryption(decrypted)
                
                if verification['accuracy'] >= 0.8:  # At least 80% of known positions match
                    results.append({
                        'key': key_string,
                        'decrypted_text': decrypted,
                        'verification': verification,
                        'score': verification['accuracy']
                    })
        
        # Sort by score (accuracy)
        results.sort(key=lambda x: x['score'], reverse=True)
        return results
    
    def analyze_transposition_possibilities(self):
        """Analyze if K4 might use transposition techniques"""
        analysis = {
            'matrix_analysis': [],
            'period_analysis': {},
            'pattern_analysis': {}
        }
        
        # Try different matrix dimensions
        text_length = len(self.k4_ciphertext)
        
        for rows in range(2, int(math.sqrt(text_length)) + 1):
            if text_length % rows == 0:
                cols = text_length // rows
                analysis['matrix_analysis'].append({
                    'rows': rows,
                    'cols': cols,
                    'feasible': True
                })
        
        return analysis
    
    def statistical_analysis_k4(self):
        """Perform statistical analysis on K4"""
        analysis = {
            'character_frequency': Counter(self.k4_ciphertext),
            'index_of_coincidence': self._calculate_ic(self.k4_ciphertext),
            'bigram_frequency': self._get_bigrams(self.k4_ciphertext),
            'repeated_patterns': self._find_repeated_patterns(self.k4_ciphertext)
        }
        
        # Compare with expected English IC
        english_ic = 0.067
        analysis['ic_analysis'] = {
            'calculated_ic': analysis['index_of_coincidence'],
            'english_ic': english_ic,
            'difference': abs(analysis['index_of_coincidence'] - english_ic),
            'cipher_type_hint': 'polyalphabetic' if analysis['index_of_coincidence'] < 0.045 else 'monoalphabetic'
        }
        
        return analysis
    
    def _calculate_ic(self, text: str) -> float:
        """Calculate Index of Coincidence"""
        text = ''.join(c for c in text if c.isalpha())
        n = len(text)
        
        if n < 2:
            return 0
        
        freq = Counter(text)
        ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
        return ic
    
    def _get_bigrams(self, text: str) -> Counter:
        """Get bigram frequencies"""
        bigrams = []
        for i in range(len(text) - 1):
            bigrams.append(text[i:i+2])
        return Counter(bigrams)
    
    def _find_repeated_patterns(self, text: str, min_length: int = 3) -> Dict:
        """Find repeated patterns in text"""
        patterns = defaultdict(list)
        
        for length in range(min_length, min(len(text) // 2, 10)):
            for i in range(len(text) - length + 1):
                pattern = text[i:i+length]
                start_pos = i + length
                
                while True:
                    pos = text.find(pattern, start_pos)
                    if pos == -1:
                        break
                    if pattern not in patterns or i not in patterns[pattern]:
                        patterns[pattern].append(i)
                    patterns[pattern].append(pos)
                    start_pos = pos + 1
        
        # Filter patterns that appear only once
        return {pattern: positions for pattern, positions in patterns.items() if len(positions) > 1}

class KryptosAnalyzer:
    """High-level analyzer for Kryptos cipher investigations"""
    
    def __init__(self):
        self.kryptos = KryptosCipher()
    
    def comprehensive_k4_analysis(self):
        """Perform comprehensive analysis of K4"""
        results = {
            'basic_info': {
                'ciphertext': self.kryptos.k4_ciphertext,
                'length': len(self.kryptos.k4_ciphertext),
                'known_plaintext_positions': len(self.kryptos.k4_known_positions)
            },
            'statistical_analysis': self.kryptos.statistical_analysis_k4(),
            'vigenere_analysis': self.kryptos.vigenere_analysis_k4(),
            'known_plaintext_analysis': self.kryptos.analyze_k4_with_known_plaintext(),
            'transposition_analysis': self.kryptos.analyze_transposition_possibilities()
        }
        
        return results
    
    def suggest_attack_strategies(self):
        """Suggest attack strategies based on analysis"""
        strategies = [
            {
                'name': 'Vigenère with Known Plaintext',
                'description': 'Use known plaintext segments to determine key characters',
                'feasibility': 'High',
                'steps': [
                    '1. Use EASTNORTHEAST, BERLIN, CLOCK to find key positions',
                    '2. Try different key lengths (likely 8-14 characters)',
                    '3. Brute force remaining unknown key positions',
                    '4. Verify against known plaintext'
                ]
            },
            {
                'name': 'Modified Vigenère Analysis',
                'description': 'Account for Kryptos-specific alphabet variations',
                'feasibility': 'Medium',
                'steps': [
                    '1. Consider the special Kryptos alphabet ordering',
                    '2. Test variations of standard Vigenère',
                    '3. Look for alphabet key shifts'
                ]
            },
            {
                'name': 'Transposition Analysis',
                'description': 'Test if transposition is combined with substitution',
                'feasibility': 'Low',
                'steps': [
                    '1. Try columnar transposition with various widths',
                    '2. Test route ciphers',
                    '3. Combine with substitution methods'
                ]
            }
        ]
        
        return strategies