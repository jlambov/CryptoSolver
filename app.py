import streamlit as st
import matplotlib.pyplot as plt
import plotly.graph_objects as go
import plotly.express as px
from collections import Counter
import re
import string
import numpy as np
import json
from ciphers import CaesarCipher, VigenereCipher, SubstitutionCipher
from analysis import FrequencyAnalysis, PatternAnalysis
from utils import TextProcessor, FileHandler
from kryptos import KryptosCipher, KryptosAnalyzer
from kryptos_visual import KryptosVisualizer, create_interactive_cipher_grid
from database import DatabaseManager, initialize_k4_plaintext
from key_testing import KeyTester
from rate_limiter import show_rate_limit_status, check_and_enforce_rate_limit, force_session_refresh_if_expired
import uuid

def main():
    st.set_page_config(
        page_title="Cryptographic Analysis Tool",
        page_icon="🔐",
        layout="wide"
    )
    
    # Initialize database with retry logic
    if 'db_manager' not in st.session_state:
        try:
            st.session_state.db_manager = DatabaseManager()
            initialize_k4_plaintext(st.session_state.db_manager)
        except Exception as e:
            # Database connection failed, continue without database features
            st.session_state.db_manager = None
    
    # Initialize session ID with secure random ID
    if 'session_id' not in st.session_state:
        import secrets
        st.session_state.session_id = secrets.token_urlsafe(16)
    
    # Check session timeout before proceeding
    force_session_refresh_if_expired()
    
    st.title("🔐 Cryptographic Analysis Tool")
    st.markdown("**Decrypt messages using multiple cipher techniques and statistical analysis**")
    
    # Sidebar for navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.radio(
        "Select Tool",
        ["Educational Info", "Text Input & Analysis", "Cipher Decryption", "Statistical Analysis", "Pattern Recognition", "Kryptos Analysis", "Database History"]
    )
    
    # Show session info and database status
    if st.session_state.db_manager:
        st.sidebar.write(f"**Session:** {st.session_state.session_id}")
        st.sidebar.write("🟢 Database connected")
        if st.sidebar.button("New Session"):
            st.session_state.session_id = str(uuid.uuid4())[:8]
            st.rerun()
    else:
        st.sidebar.write(f"**Session:** {st.session_state.session_id}")
        st.sidebar.write("🟡 Database offline (analysis only)")
    
    # Show rate limit status with live countdown
    show_rate_limit_status()
    
    if page == "Educational Info":
        educational_info_page()
    elif page == "Text Input & Analysis":
        text_input_page()
    elif page == "Cipher Decryption":
        cipher_decryption_page()
    elif page == "Statistical Analysis":
        statistical_analysis_page()
    elif page == "Pattern Recognition":
        pattern_recognition_page()
    elif page == "Kryptos Analysis":
        kryptos_analysis_page()
    elif page == "Database History":
        database_history_page()

def text_input_page():
    st.header("📝 Text Input & Processing")
    
    # Text input methods
    input_method = st.radio("Choose input method:", ["Select Predefined", "Type/Paste Text"])
    
    ciphertext = ""
    if input_method == "Select Predefined":
        predefined_option = st.selectbox(
            "Select cipher text:",
            ["K4 Cipher Text (97 characters)", "Custom"]
        )
        
        if predefined_option == "K4 Cipher Text (97 characters)":
            ciphertext = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
            st.text_area("K4 Cipher Text:", value=ciphertext, height=100, disabled=True)
        else:
            ciphertext = st.text_area("Enter custom encrypted text:", height=200, placeholder="Paste your encrypted message here...")
    
    elif input_method == "Type/Paste Text":
        ciphertext = st.text_area("Enter encrypted text:", height=200, placeholder="Paste your encrypted message here...", max_chars=50000)
    
    if ciphertext:
        # Store in session state (activity tracking handled by rate limiter)
        st.session_state.ciphertext = ciphertext
        
        # Text processing options
        st.subheader("🛠️ Text Processing Options")
        col1, col2 = st.columns(2)
        
        with col1:
            remove_spaces = st.checkbox("Remove spaces")
            remove_punctuation = st.checkbox("Remove punctuation")
            to_uppercase = st.checkbox("Convert to uppercase")
        
        with col2:
            remove_numbers = st.checkbox("Remove numbers")
            keep_only_letters = st.checkbox("Keep only letters")
        
        # Process text
        processor = TextProcessor()
        processed_text = processor.process_text(
            ciphertext,
            remove_spaces=remove_spaces,
            remove_punctuation=remove_punctuation,
            to_uppercase=to_uppercase,
            remove_numbers=remove_numbers,
            keep_only_letters=keep_only_letters
        )
        
        if processed_text != ciphertext:
            st.subheader("Processed Text:")
            st.text_area("Processed result:", value=processed_text, height=100, label_visibility="collapsed")
            st.session_state.processed_text = processed_text
        
        # Basic text statistics
        st.subheader("📊 Basic Statistics")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Characters", len(ciphertext))
        with col2:
            st.metric("Letters Only", len([c for c in ciphertext if c.isalpha()]))
        with col3:
            st.metric("Unique Characters", len(set(ciphertext.upper())))
        with col4:
            st.metric("Words", len(ciphertext.split()))

def cipher_decryption_page():
    st.header("🔓 Cipher Decryption")
    
    if 'ciphertext' not in st.session_state:
        st.warning("Please input text in the 'Text Input & Analysis' section first.")
        return
    
    ciphertext = st.session_state.get('processed_text', st.session_state.ciphertext)
    
    # Advanced Key Testing Section
    st.subheader("🎯 Advanced Key Testing")
    
    # Custom key input
    st.write("**Custom Keys:** Enter specific keys to test (comma-separated)")
    custom_keys_input = st.text_input(
        "Custom keys:", 
        value="HOWS, UNDERGRUUND, DESPARATLY, IQLUSION",
        help="Enter keys separated by commas. These will be tested first with highest priority.",
        max_chars=1000
    )
    
    # Parse custom keys
    custom_keys = []
    if custom_keys_input.strip():
        custom_keys = [key.strip().upper() for key in custom_keys_input.split(',') if key.strip()]
    
    # Testing options
    col1, col2, col3 = st.columns(3)
    with col1:
        max_keys = st.slider("Maximum keys to test:", 500, 10000, 2000, step=500)
    with col2:
        test_mode = st.selectbox("Test mode:", ["Comprehensive Attack", "Specific Keys Only"])
    with col3:
        if test_mode == "Comprehensive Attack":
            if st.button("🚀 Launch Attack", type="primary"):
                if not check_and_enforce_rate_limit('comprehensive_attack'):
                    st.stop()
                
                with st.spinner("Testing multiple keys and cipher variants..."):
                    key_tester = KeyTester()
                    attack_results = key_tester.comprehensive_attack(
                        ciphertext, 
                        max_keys=max_keys, 
                        custom_keys=custom_keys
                    )
                    
                    st.success(f"Attack completed! Tested {attack_results['total_keys_tested']} keys in {attack_results['execution_time']:.2f} seconds")
                    
                    if custom_keys:
                        st.info(f"Priority tested custom keys: {', '.join(custom_keys)}")
                    
                    if attack_results['best_results']:
                        st.subheader("🏆 Top Results")
                        
                        # Display best result prominently
                        best = attack_results['best_results'][0]
                        col_a, col_b = st.columns([1, 2])
                        with col_a:
                            st.metric("Best Score", f"{best[3]:.2f}")
                            st.write(f"**Key:** {best[0]}")
                            st.write(f"**Method:** {best[1]}")
                        with col_b:
                            st.text_area("Decrypted Text:", best[2], height=150)
                        
                        # Show if known plaintext was found
                        if attack_results.get('known_plaintext_matches', 0) > 0:
                            st.success(f"✅ Found {attack_results['known_plaintext_matches']:.1f} known plaintext matches!")
                        
                        # Show top 10 results in expandable section
                        with st.expander("View All Top Results"):
                            for i, (key, method, decrypted, score) in enumerate(attack_results['best_results'][:10], 1):
                                st.write(f"**{i}. Score: {score:.2f} | Key: {key} | Method: {method}**")
                                st.text(decrypted[:100] + ("..." if len(decrypted) > 100 else ""))
                                if i < 10:
                                    st.divider()
                    else:
                        st.warning("No significant results found. The cipher may require different techniques.")
        
        else:  # Specific Keys Only
            if st.button("🔍 Test Specific Keys", type="primary") and custom_keys:
                if not check_and_enforce_rate_limit('specific_key_test'):
                    st.stop()
                
                with st.spinner(f"Testing {len(custom_keys)} specific keys with all variants..."):
                    key_tester = KeyTester()
                    specific_results = key_tester.test_specific_keys(ciphertext, custom_keys)
                    
                    st.success(f"Testing completed in {specific_results['execution_time']:.2f} seconds")
                    
                    if specific_results['best_overall']:
                        st.subheader("🏆 Best Overall Result")
                        best = specific_results['best_overall']
                        
                        col_a, col_b = st.columns([1, 2])
                        with col_a:
                            st.metric("Best Score", f"{best['score']:.2f}")
                            st.write(f"**Key:** {best['key']}")
                            st.write(f"**Method:** {best['method']}")
                        with col_b:
                            st.text_area("Decrypted Text:", best['decryption'], height=150)
                    
                    # Show detailed results for each key
                    st.subheader("📊 Detailed Results by Key")
                    for key, results in specific_results['detailed_results'].items():
                        with st.expander(f"Key: {key} (Best Score: {results['best_variant']['score']:.2f})"):
                            st.write(f"**Best Method:** {results['best_variant']['method']}")
                            st.text_area(f"Best Decryption for {key}:", results['best_variant']['decryption'], height=100)
                            
                            # Show all variants
                            st.write("**All Variants:**")
                            all_variants = {**results['vigenere_variants'], **results['transposition_variants']}
                            for method, (decrypted, score) in all_variants.items():
                                if score > 0:
                                    st.write(f"- {method}: Score {score:.2f}")
                                    if score > 1.0:  # Show text for promising results
                                        st.text(decrypted[:80] + ("..." if len(decrypted) > 80 else ""))
            elif not custom_keys:
                st.warning("Please enter custom keys to test.")
    
    st.divider()
    
    # Standard Cipher Testing
    st.subheader("🔧 Standard Cipher Testing")
    cipher_type = st.selectbox(
        "Select cipher type:",
        ["Caesar Cipher", "Vigenère Cipher", "Substitution Cipher", "Auto-detect"]
    )
    
    if cipher_type == "Caesar Cipher":
        caesar_decryption(ciphertext)
    elif cipher_type == "Vigenère Cipher":
        vigenere_decryption(ciphertext)
    elif cipher_type == "Substitution Cipher":
        substitution_decryption(ciphertext)
    elif cipher_type == "Auto-detect":
        auto_detect_decryption(ciphertext)

def caesar_decryption(ciphertext):
    st.subheader("🔄 Caesar Cipher Decryption")
    
    caesar = CaesarCipher()
    
    # Manual shift input
    col1, col2 = st.columns(2)
    
    with col1:
        manual_shift = st.number_input("Try specific shift:", min_value=0, max_value=25, value=0)
        if st.button("Decrypt with shift"):
            if check_and_enforce_rate_limit('cipher_decrypt'):
                result = caesar.decrypt(ciphertext, manual_shift)
                st.text_area("Result:", value=result, height=100)
    
    with col2:
        # Brute force all shifts
        if st.button("Try all shifts (Brute Force)"):
            if check_and_enforce_rate_limit('cipher_decrypt'):
                st.subheader("All possible shifts:")
                for shift in range(26):
                    result = caesar.decrypt(ciphertext, shift)
                    st.write(f"**Shift {shift}:** {result[:100]}{'...' if len(result) > 100 else ''}")

def vigenere_decryption(ciphertext):
    st.subheader("🗝️ Vigenère Cipher Decryption")
    
    vigenere = VigenereCipher()
    
    # Known key decryption
    key = st.text_input("Enter key (if known):")
    if key and st.button("Decrypt with key"):
        try:
            result = vigenere.decrypt(ciphertext, key)
            st.text_area("Result:", value=result, height=100)
        except Exception as e:
            st.error(f"Error: {str(e)}")
    
    # Key length analysis
    st.subheader("🔍 Key Length Analysis")
    if st.button("Analyze key length"):
        key_lengths = vigenere.analyze_key_length(ciphertext)
        
        fig = go.Figure(data=go.Bar(x=list(range(2, min(21, len(ciphertext)//2))), 
                                   y=[key_lengths.get(i, 0) for i in range(2, min(21, len(ciphertext)//2))]))
        fig.update_layout(title="Probable Key Lengths (Index of Coincidence)", 
                         xaxis_title="Key Length", yaxis_title="IC Score")
        st.plotly_chart(fig)
        
        # Show most likely key lengths
        sorted_lengths = sorted(key_lengths.items(), key=lambda x: x[1], reverse=True)[:5]
        st.write("Most likely key lengths:")
        for length, score in sorted_lengths:
            st.write(f"Length {length}: Score {score:.4f}")

def substitution_decryption(ciphertext):
    st.subheader("🔀 Substitution Cipher Decryption")
    
    substitution = SubstitutionCipher()
    
    # Manual mapping
    st.write("**Manual Character Mapping:**")
    col1, col2 = st.columns(2)
    
    with col1:
        cipher_char = st.text_input("Cipher character:", max_chars=1).upper()
    with col2:
        plain_char = st.text_input("Plain character:", max_chars=1).upper()
    
    if 'substitution_map' not in st.session_state:
        st.session_state.substitution_map = {}
    
    if cipher_char and plain_char and st.button("Add mapping"):
        st.session_state.substitution_map[cipher_char] = plain_char
        st.success(f"Added mapping: {cipher_char} → {plain_char}")
    
    # Display current mappings
    if st.session_state.substitution_map:
        st.write("**Current mappings:**")
        mapping_text = " | ".join([f"{k}→{v}" for k, v in st.session_state.substitution_map.items()])
        st.write(mapping_text)
        
        # Apply current mappings
        result = substitution.decrypt_with_mapping(ciphertext, st.session_state.substitution_map)
        st.text_area("Partial decryption:", value=result, height=100)
        
        if st.button("Clear mappings"):
            st.session_state.substitution_map = {}
            st.rerun()
    
    # Frequency-based suggestion
    if st.button("Suggest mappings based on frequency"):
        suggestions = substitution.suggest_mappings(ciphertext)
        st.write("**Suggested mappings based on frequency analysis:**")
        for cipher_char, plain_char in suggestions.items():
            st.write(f"{cipher_char} → {plain_char} (most common letters)")

def auto_detect_decryption(ciphertext):
    st.subheader("🤖 Auto-detect Cipher Type")
    
    if st.button("Analyze cipher type"):
        # Simple heuristics for cipher detection
        analysis_results = []
        
        # Check for Caesar cipher (try all shifts and score)
        caesar = CaesarCipher()
        best_caesar_score = 0
        best_caesar_shift = 0
        best_caesar_text = ""
        
        for shift in range(26):
            result = caesar.decrypt(ciphertext, shift)
            score = score_english_text(result)
            if score > best_caesar_score:
                best_caesar_score = score
                best_caesar_shift = shift
                best_caesar_text = result
        
        analysis_results.append(("Caesar Cipher", best_caesar_score, f"Shift {best_caesar_shift}", best_caesar_text))
        
        # Check for Vigenère (analyze index of coincidence)
        vigenere = VigenereCipher()
        ic_score = calculate_index_of_coincidence(ciphertext)
        analysis_results.append(("Vigenère Cipher", ic_score, f"IC: {ic_score:.4f}", "Key analysis needed"))
        
        # Check for substitution (analyze frequency distribution)
        substitution = SubstitutionCipher()
        freq_score = analyze_frequency_distribution(ciphertext)
        analysis_results.append(("Substitution Cipher", freq_score, f"Freq score: {freq_score:.4f}", "Frequency analysis needed"))
        
        # Sort by score
        analysis_results.sort(key=lambda x: x[1], reverse=True)
        
        st.write("**Cipher type analysis results:**")
        for cipher_type, score, details, preview in analysis_results:
            with st.expander(f"{cipher_type} (Score: {score:.4f})"):
                st.write(f"Details: {details}")
                if preview != "Key analysis needed" and preview != "Frequency analysis needed":
                    st.write(f"Preview: {preview[:200]}{'...' if len(preview) > 200 else ''}")

def statistical_analysis_page():
    st.header("📈 Statistical Analysis")
    
    if 'ciphertext' not in st.session_state:
        st.warning("Please input text in the 'Text Input & Analysis' section first.")
        return
    
    ciphertext = st.session_state.get('processed_text', st.session_state.ciphertext)
    analyzer = FrequencyAnalysis()
    
    # Frequency analysis
    st.subheader("📊 Frequency Analysis")
    
    # Character frequency
    char_freq = analyzer.character_frequency(ciphertext)
    if char_freq:
        # Create frequency chart
        chars, freqs = zip(*char_freq.most_common())
        
        fig = px.bar(x=chars[:26], y=freqs[:26], 
                    title="Character Frequency Distribution",
                    labels={'x': 'Characters', 'y': 'Frequency'})
        st.plotly_chart(fig)
        
        # Compare with English frequency
        english_freq = analyzer.english_frequency_order()
        
        col1, col2 = st.columns(2)
        with col1:
            st.write("**Cipher text frequency order:**")
            st.write("".join(chars[:26]))
        with col2:
            st.write("**Expected English frequency order:**")
            st.write("".join(english_freq))
    
    # Bigram analysis
    st.subheader("🔗 Bigram Analysis")
    if st.button("Analyze bigrams"):
        bigrams = analyzer.bigram_frequency(ciphertext)
        if bigrams:
            st.write("**Most common bigrams:**")
            for bigram, count in bigrams.most_common(10):
                st.write(f"{bigram}: {count}")
    
    # Trigram analysis
    st.subheader("🔗 Trigram Analysis")
    if st.button("Analyze trigrams"):
        trigrams = analyzer.trigram_frequency(ciphertext)
        if trigrams:
            st.write("**Most common trigrams:**")
            for trigram, count in trigrams.most_common(10):
                st.write(f"{trigram}: {count}")
    
    # Index of Coincidence
    st.subheader("🎯 Index of Coincidence")
    ic = calculate_index_of_coincidence(ciphertext)
    st.metric("Index of Coincidence", f"{ic:.4f}")
    
    interpretation = ""
    if ic > 0.065:
        interpretation = "Likely monoalphabetic cipher (Caesar, substitution)"
    elif ic < 0.045:
        interpretation = "Likely polyalphabetic cipher (Vigenère, etc.)"
    else:
        interpretation = "Ambiguous - could be either type"
    
    st.write(f"**Interpretation:** {interpretation}")

def pattern_recognition_page():
    st.header("🔍 Pattern Recognition")
    
    if 'ciphertext' not in st.session_state:
        st.warning("Please input text in the 'Text Input & Analysis' section first.")
        return
    
    ciphertext = st.session_state.get('processed_text', st.session_state.ciphertext)
    pattern_analyzer = PatternAnalysis()
    
    # Repeated sequences
    st.subheader("🔄 Repeated Sequences")
    min_length = st.slider("Minimum sequence length:", 2, 10, 3)
    
    if st.button("Find repeated sequences"):
        repeated = pattern_analyzer.find_repeated_sequences(ciphertext, min_length)
        if repeated:
            st.write("**Repeated sequences found:**")
            for seq, positions in repeated.items():
                distances = [positions[i+1] - positions[i] for i in range(len(positions)-1)]
                st.write(f"**'{seq}'** appears at positions: {positions}")
                if distances:
                    st.write(f"Distances between occurrences: {distances}")
                    # Find GCD of distances for Vigenère key length hints
                    import math
                    if len(distances) > 1:
                        gcd = distances[0]
                        for d in distances[1:]:
                            gcd = math.gcd(gcd, d)
                        st.write(f"GCD of distances: {gcd} (possible key length)")
                st.write("---")
        else:
            st.write("No repeated sequences found.")

def kryptos_analysis_page():
    st.header("🏛️ Kryptos Cipher Analysis")
    st.markdown("**Specialized tools for analyzing the Kryptos sculpture cipher, including the unsolved K4 section**")
    
    analyzer = KryptosAnalyzer()
    kryptos = KryptosCipher()
    
    # Kryptos sections overview
    st.subheader("📜 Kryptos Overview")
    
    # Status indicators for all sections
    col_k1, col_k2, col_k3, col_k4 = st.columns(4)
    
    with col_k1:
        st.metric("K1", "✅ SOLVED", delta="Vigenère")
    with col_k2:
        st.metric("K2", "✅ SOLVED", delta="Vigenère")
    with col_k3:
        st.metric("K3", "✅ SOLVED", delta="Transposition")
    with col_k4:
        st.metric("K4", "❌ UNSOLVED", delta="97 chars")
    
    with st.expander("🏛️ About Kryptos Sculpture"):
        st.markdown("""
        **Artist:** Jim Sanborn  
        **Location:** CIA Headquarters, Langley, Virginia, USA  
        **Installed:** 1990  
        **Description:** An encrypted sculpture containing four separate coded messages (K1, K2, K3, K4). The first three have been solved, but K4 remains one of the world's most famous unsolved ciphers.
        
        ---
        
        **K1 (SOLVED 1999):**
        *"BETWEEN SUBTLE SHADING AND THE ABSENCE OF LIGHT LIES THE NUANCE OF IQLUSION"*
        
        **K2 (SOLVED 1999):**
        *"IT WAS TOTALLY INVISIBLE HOWS THAT POSSIBLE ? THEY USED THE EARTHS MAGNETIC FIELD X THE INFORMATION WAS GATHERED AND TRANSMITTED UNDERGRUUND TO AN UNKNOWN LOCATION X DOES LANGLEY KNOW ABOUT THIS ? THEY SHOULD ITS BURIED OUT THERE SOMEWHERE X WHO KNOWS THE EXACT LOCATION ? ONLY WW THIS WAS HIS LAST MESSAGE X THIRTY EIGHT DEGREES FIFTY SEVEN MINUTES SIX POINT FIVE SECONDS NORTH SEVENTY SEVEN DEGREES EIGHT MINUTES FORTY FOUR SECONDS WEST X LAYER TWO"*
        
        **K3 (SOLVED 2010):**
        *"SLOWLY DESPARATLY SLOWLY THE REMAINS OF PASSAGE DEBRIS THAT ENCUMBERED THE LOWER PART OF THE DOORWAY WAS REMOVED WITH TREMBLING HANDS I MADE A TINY BREACH IN THE UPPER LEFT HAND CORNER AND THEN WIDENING THE HOLE A LITTLE I INSERTED THE CANDLE AND PEERED IN THE HOT AIR ESCAPING FROM THE CHAMBER CAUSED THE FLAME TO FLICKER BUT PRESENTLY DETAILS OF THE ROOM WITHIN EMERGED FROM THE MIST X CAN YOU SEE ANYTHING Q ?"*
        
        ---
        
        **K4 (UNSOLVED):**
        - **Length:** 97 characters
        - **Known Plaintext Segments:**
          - EASTNORTHEAST (positions 22-34)
          - BERLIN (positions 64-69)
          - CLOCK (positions 70-74)
        
        These clues were released by Jim Sanborn to assist codebreakers in solving the final section.
        """)
    
    # K4 Analysis Section
    st.subheader("🔍 K4 Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**K4 Ciphertext (97 characters):**")
        
        # Format ciphertext with positions for better visualization
        formatted_cipher = ""
        for i, char in enumerate(kryptos.k4_ciphertext):
            if i > 0 and i % 10 == 0:
                formatted_cipher += "\n"
            formatted_cipher += char
        
        st.code(formatted_cipher, language=None)
        
        # Position grid visualization
        st.write("**Position Grid (Red = Known, Gray = Unknown):**")
        
        # Create HTML grid for better visualization
        grid_html = """
        <style>
        .cipher-grid {
            display: grid;
            grid-template-columns: repeat(10, 1fr);
            gap: 2px;
            font-family: monospace;
            font-size: 14px;
            margin: 10px 0;
        }
        .cipher-cell {
            width: 25px;
            height: 25px;
            display: flex;
            align-items: center;
            justify-content: center;
            border: 1px solid #ddd;
            font-weight: bold;
        }
        .known-cell {
            background-color: #ff6b6b;
            color: white;
        }
        .unknown-cell {
            background-color: #f0f0f0;
            color: #333;
        }
        </style>
        <div class="cipher-grid">
        """
        
        for i, char in enumerate(kryptos.k4_ciphertext):
            if i in kryptos.k4_known_positions:
                grid_html += f'<div class="cipher-cell known-cell">{char}</div>'
            else:
                grid_html += f'<div class="cipher-cell unknown-cell">{char}</div>'
        
        grid_html += "</div>"
        st.markdown(grid_html, unsafe_allow_html=True)
        
        # Interactive cipher grid
        st.write("**Interactive Cipher Grid:**")
        visualizer = KryptosVisualizer()
        interactive_fig = create_interactive_cipher_grid(kryptos.k4_ciphertext, kryptos.k4_known_positions)
        st.plotly_chart(interactive_fig, use_container_width=True)
        
        col_a, col_b = st.columns(2)
        with col_a:
            st.metric("Total Length", len(kryptos.k4_ciphertext))
        with col_b:
            st.metric("Known Positions", len(kryptos.k4_known_positions))
    
    with col2:
        st.write("**Known Plaintext Mapping:**")
        
        # Create a visual table for known positions
        known_data = []
        for pos, char in sorted(kryptos.k4_known_positions.items()):
            known_data.append({
                'Position': pos + 1,
                'Cipher': kryptos.k4_ciphertext[pos],
                'Plain': char,
                'Segment': 'EASTNORTHEAST' if 21 <= pos <= 33 else 'BERLIN' if 63 <= pos <= 68 else 'CLOCK'
            })
        
        # Display as dataframe for better visualization
        import pandas as pd
        df = pd.DataFrame(known_data)
        st.dataframe(df, hide_index=True)
        
        # Legend
        st.write("**Legend:**")
        st.write("🔴 Known position | ⚪ Unknown position")
    
    # Analysis Tools
    st.subheader("🔬 Analysis Tools")
    
    analysis_type = st.selectbox(
        "Select analysis type:",
        ["Comprehensive Analysis", "Vigenère Key Recovery", "Statistical Analysis", "Attack Strategies"]
    )
    
    if analysis_type == "Comprehensive Analysis":
        if st.button("Run Comprehensive Analysis"):
            with st.spinner("Analyzing K4..."):
                results = analyzer.comprehensive_k4_analysis()
                
                # Save analysis to database (non-blocking)
                if st.session_state.db_manager:
                    try:
                        # Create session if not exists
                        st.session_state.db_manager.create_analysis_session(
                            st.session_state.session_id,
                            kryptos.k4_ciphertext,
                            'K4',
                            'Comprehensive analysis of K4 cipher'
                        )
                        
                        # Save statistical analysis
                        st.session_state.db_manager.save_statistical_analysis(
                            st.session_state.session_id,
                            'comprehensive',
                            results['statistical_analysis']
                        )
                        st.success("Analysis saved to database")
                    except Exception as e:
                        st.info("Analysis completed (database temporarily unavailable)")
                
                # Display results
                st.subheader("📊 Analysis Results")
                
                # Basic info
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Text Length", results['basic_info']['length'])
                with col2:
                    st.metric("Known Positions", results['basic_info']['known_plaintext_positions'])
                with col3:
                    ic = results['statistical_analysis']['index_of_coincidence']
                    st.metric("Index of Coincidence", f"{ic:.4f}")
                
                # Statistical analysis
                st.subheader("📈 Statistical Analysis")
                stat_analysis = results['statistical_analysis']
                
                # Character frequency chart
                char_freq = stat_analysis['character_frequency']
                if char_freq:
                    chars, freqs = zip(*char_freq.most_common())
                    fig = px.bar(x=chars[:20], y=freqs[:20], 
                                title="K4 Character Frequency Distribution",
                                labels={'x': 'Characters', 'y': 'Frequency'})
                    st.plotly_chart(fig)
                
                # IC Analysis
                ic_analysis = stat_analysis['ic_analysis']
                st.write(f"**Cipher Type Indication:** {ic_analysis['cipher_type_hint']}")
                st.write(f"**IC vs English:** {ic_analysis['difference']:.4f} difference")
                
                # Vigenère Analysis
                st.subheader("🔑 Vigenère Key Analysis")
                vigenere_results = results['vigenere_analysis']
                
                if vigenere_results:
                    # Create visualization for key analysis
                    visualizer = KryptosVisualizer()
                    key_chart = visualizer.create_key_analysis_chart(vigenere_results)
                    if key_chart:
                        st.plotly_chart(key_chart, use_container_width=True)
                    
                    best_key_lengths = sorted(vigenere_results.items(), 
                                            key=lambda x: x[1]['confidence'], reverse=True)[:5]
                    
                    st.write("**Most Promising Key Lengths:**")
                    for key_len, analysis in best_key_lengths:
                        if analysis['confidence'] > 0:
                            st.write(f"**Length {key_len}:** Confidence {analysis['confidence']:.2f}")
                            partial_key = ''.join(analysis['partial_key'])
                            st.write(f"Partial key: `{partial_key}`")
                            st.write(f"Known positions: {analysis['key_positions_found']}/{key_len}")
                            if analysis['conflicts']:
                                st.write(f"⚠️ Conflicts: {len(analysis['conflicts'])}")
                            st.write("---")
    
    elif analysis_type == "Vigenère Key Recovery":
        st.subheader("🔓 Vigenère Key Recovery")
        
        col1, col2 = st.columns(2)
        
        with col1:
            key_length = st.number_input("Key length to test:", min_value=2, max_value=20, value=8)
        
        with col2:
            max_brute_force = st.number_input("Max unknown positions for brute force:", min_value=1, max_value=5, value=3)
        
        if st.button("Analyze Key Length"):
            with st.spinner("Analyzing key length..."):
                key_analysis = kryptos._analyze_key_length_k4(key_length)
                
                st.write(f"**Analysis for key length {key_length}:**")
                st.write(f"Confidence: {key_analysis['confidence']:.2f}")
                st.write(f"Known positions: {key_analysis['key_positions_found']}/{key_length}")
                
                partial_key = ''.join(key_analysis['partial_key'])
                st.write(f"Partial key: `{partial_key}`")
                
                if key_analysis['conflicts']:
                    st.error(f"Conflicts detected: {len(key_analysis['conflicts'])}")
                    for conflict in key_analysis['conflicts']:
                        st.write(f"Position {conflict['position']}: {conflict['existing']} vs {conflict['new']}")
                
                # Try brute force if feasible
                unknown_positions = [i for i, char in enumerate(key_analysis['partial_key']) if char == '?']
                
                if len(unknown_positions) <= max_brute_force and key_analysis['confidence'] > 0:
                    st.write(f"**Attempting brute force for {len(unknown_positions)} unknown positions...**")
                    
                    known_positions = {i: char for i, char in enumerate(key_analysis['partial_key']) if char != '?'}
                    
                    with st.spinner("Brute forcing key..."):
                        brute_results = kryptos.brute_force_partial_key(known_positions, max_brute_force)
                    
                    if brute_results:
                        st.success(f"Found {len(brute_results)} potential keys!")
                        
                        for i, result in enumerate(brute_results[:10]):  # Show top 10
                            with st.expander(f"Key {i+1}: {result['key']} (Score: {result['score']:.2f})"):
                                st.write(f"**Key:** `{result['key']}`")
                                st.write(f"**Accuracy:** {result['verification']['accuracy']:.2f}")
                                # Visual decryption result
                                decrypted_visual = ""
                                for j, char in enumerate(result['decrypted_text']):
                                    if j in kryptos.k4_known_positions:
                                        if char == kryptos.k4_known_positions[j]:
                                            decrypted_visual += f"✅{char}"
                                        else:
                                            decrypted_visual += f"❌{char}"
                                    else:
                                        decrypted_visual += f"❓{char}"
                                    if (j + 1) % 10 == 0:
                                        decrypted_visual += "\n"
                                
                                st.text(decrypted_visual)
                                st.caption("✅ Correct match | ❌ Incorrect match | ❓ Unknown position")
                                
                                if result['verification']['mismatches']:
                                    st.write("**Mismatches:**")
                                    for mismatch in result['verification']['mismatches']:
                                        st.write(f"Pos {mismatch['position']}: Expected {mismatch['expected']}, Got {mismatch['actual']}")
                    else:
                        st.warning("No valid keys found with current parameters.")
    
    elif analysis_type == "Statistical Analysis":
        if st.button("Run Statistical Analysis"):
            with st.spinner("Running statistical analysis..."):
                stats = kryptos.statistical_analysis_k4()
                
                # Character frequency
                st.subheader("📊 Character Frequency")
                char_freq = stats['character_frequency']
                chars, freqs = zip(*char_freq.most_common())
                
                fig = px.bar(x=chars, y=freqs, 
                            title="K4 Character Frequency",
                            labels={'x': 'Characters', 'y': 'Frequency'})
                st.plotly_chart(fig)
                
                # Index of Coincidence
                st.subheader("🎯 Index of Coincidence Analysis")
                ic_info = stats['ic_analysis']
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("K4 IC", f"{ic_info['calculated_ic']:.4f}")
                with col2:
                    st.metric("English IC", f"{ic_info['english_ic']:.4f}")
                with col3:
                    st.metric("Difference", f"{ic_info['difference']:.4f}")
                
                st.write(f"**Cipher Type Indication:** {ic_info['cipher_type_hint']}")
                
                # Bigram analysis
                st.subheader("🔗 Bigram Analysis")
                bigrams = stats['bigram_frequency']
                if bigrams:
                    st.write("**Most common bigrams:**")
                    for bigram, count in bigrams.most_common(10):
                        st.write(f"`{bigram}`: {count}")
                
                # Repeated patterns
                st.subheader("🔄 Repeated Patterns")
                patterns = stats['repeated_patterns']
                if patterns:
                    for pattern, positions in patterns.items():
                        distances = [positions[i+1] - positions[i] for i in range(len(positions)-1)]
                        st.write(f"**Pattern `{pattern}`:** positions {positions}, distances {distances}")
                else:
                    st.write("No repeated patterns found.")
    
    elif analysis_type == "Attack Strategies":
        strategies = analyzer.suggest_attack_strategies()
        
        st.subheader("⚔️ Suggested Attack Strategies")
        
        for strategy in strategies:
            with st.expander(f"{strategy['name']} (Feasibility: {strategy['feasibility']})"):
                st.write(f"**Description:** {strategy['description']}")
                st.write("**Steps:**")
                for step in strategy['steps']:
                    st.write(step)
    
    # Manual key testing
    st.subheader("🧪 Manual Key Testing")
    
    test_key = st.text_input("Enter key to test:", placeholder="e.g., KRYPTOS")
    
    if test_key and st.button("Test Key"):
        with st.spinner("Testing key..."):
            decrypted = kryptos.attempt_k4_decryption(test_key)
            
            if decrypted:
                verification = kryptos.verify_decryption(decrypted)
                
                # Save to database (non-blocking)
                if st.session_state.db_manager:
                    try:
                        st.session_state.db_manager.save_key_attempt(
                            st.session_state.session_id,
                            test_key,
                            decrypted,
                            verification['accuracy'],
                            verification['matches'],
                            verification['total_known'],
                            'manual_test',
                            f"Manual key test by user"
                        )
                    except Exception as e:
                        # Don't show error to user, just log it
                        pass
                
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"**Key:** `{test_key}`")
                    st.write(f"**Accuracy:** {verification['accuracy']:.2f}")
                    st.write(f"**Matches:** {verification['matches']}/{verification['total_known']}")
                
                with col2:
                    if verification['mismatches']:
                        st.write("**Mismatches:**")
                        for mismatch in verification['mismatches'][:5]:  # Show first 5
                            st.write(f"Pos {mismatch['position']}: Expected {mismatch['expected']}, Got {mismatch['actual']}")
                
                # Visual decryption result for manual testing
                decrypted_visual = ""
                for j, char in enumerate(decrypted):
                    if j in kryptos.k4_known_positions:
                        if char == kryptos.k4_known_positions[j]:
                            decrypted_visual += f"✅{char}"
                        else:
                            decrypted_visual += f"❌{char}"
                    else:
                        decrypted_visual += f"❓{char}"
                    if (j + 1) % 10 == 0:
                        decrypted_visual += "\n"
                
                st.write("**Visual Decryption Result:**")
                st.text(decrypted_visual)
                st.caption("✅ Correct match | ❌ Incorrect match | ❓ Unknown position")
                
                # Also show as plain text
                st.text_area("Plain Text Result:", decrypted, height=100)
            else:
                st.error("Failed to decrypt with given key.")

def database_history_page():
    st.header("🗄️ Database History")
    
    if not st.session_state.db_manager:
        st.error("Database not available")
        return
    
    db = st.session_state.db_manager
    
    # Overall statistics
    st.subheader("📊 Overall Statistics")
    try:
        stats = db.get_analysis_statistics()
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Sessions", stats['total_sessions'])
        with col2:
            st.metric("Total Attempts", stats['total_attempts'])
        with col3:
            st.metric("Successful Attempts", stats['successful_attempts'])
        with col4:
            st.metric("Success Rate", f"{stats['success_rate']:.1%}")
        
        if stats['best_accuracy'] > 0:
            st.write(f"**Best Result:** {stats['best_accuracy']:.2f} accuracy with key `{stats['best_key']}`")
        
    except Exception as e:
        st.error(f"Error loading statistics: {e}")
    
    # Current session history
    st.subheader("📋 Current Session History")
    try:
        session_history = db.get_session_history(st.session_state.session_id)
        
        if session_history and session_history['key_attempts']:
            st.write(f"**Session:** {st.session_state.session_id}")
            
            # Key attempts table
            attempts_data = []
            for attempt in session_history['key_attempts'][:20]:  # Show last 20
                attempts_data.append({
                    'Key': attempt['key_value'],
                    'Length': attempt['key_length'],
                    'Accuracy': f"{attempt['accuracy_score']:.2f}",
                    'Method': attempt['cipher_method'] or 'Unknown',
                    'Time': attempt['created_at'].strftime('%H:%M:%S'),
                    'Success': '✅' if attempt['is_successful'] else '❌'
                })
            
            if attempts_data:
                import pandas as pd
                df = pd.DataFrame(attempts_data)
                st.dataframe(df, hide_index=True)
            
            # Show decryption for best attempt
            best_attempt = session_history['key_attempts'][0]
            if best_attempt['accuracy_score'] > 0:
                with st.expander(f"Best Result: {best_attempt['key_value']} (Score: {best_attempt['accuracy_score']:.2f})"):
                    st.text(best_attempt['decrypted_text'])
        else:
            st.info("No key attempts in current session yet")
    
    except Exception as e:
        st.error(f"Error loading session history: {e}")
    
    # Search functionality
    st.subheader("🔍 Search Keys")
    search_pattern = st.text_input("Search for keys containing:")
    
    if search_pattern:
        try:
            similar_keys = db.search_similar_keys(search_pattern, limit=10)
            
            if similar_keys:
                st.write(f"**Found {len(similar_keys)} keys containing '{search_pattern}':**")
                for key_data in similar_keys:
                    st.write(f"• `{key_data['key_value']}` - Accuracy: {key_data['accuracy_score']:.2f} - Method: {key_data['cipher_method'] or 'Unknown'}")
            else:
                st.info("No matching keys found")
        except Exception as e:
            st.error(f"Error searching keys: {e}")
    
    # Known plaintext management
    st.subheader("📝 Known Plaintext Segments")
    try:
        k4_segments = db.get_known_plaintext('K4')
        
        if k4_segments:
            segments_data = []
            for seg in k4_segments:
                segments_data.append({
                    'Start': seg['position_start'],
                    'End': seg['position_end'],
                    'Text': seg['plaintext'],
                    'Source': seg['source'],
                    'Confidence': f"{seg['confidence']:.1f}"
                })
            
            import pandas as pd
            df = pd.DataFrame(segments_data)
            st.dataframe(df, hide_index=True)
    
    except Exception as e:
        st.error(f"Error loading known plaintext: {e}")
    
    # Export functionality
    st.subheader("📤 Export Data")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("Export Current Session"):
            try:
                session_data = db.get_session_history(st.session_state.session_id)
                if session_data:
                    st.download_button(
                        label="Download Session Data (JSON)",
                        data=json.dumps(session_data, indent=2, default=str),
                        file_name=f"kryptos_session_{st.session_state.session_id}.json",
                        mime="application/json"
                    )
                else:
                    st.info("No session data to export")
            except Exception as e:
                st.error(f"Error exporting session: {e}")
    
    with col2:
        if st.button("Clear Current Session"):
            if st.button("Confirm Clear Session", type="primary"):
                # Note: We don't actually delete from DB, just start new session
                st.session_state.session_id = str(uuid.uuid4())[:8]
                st.success("Started new session")
                st.rerun()


    
    # Character positions
    st.subheader("📍 Character Position Analysis")
    target_char = st.text_input("Analyze positions of character:", max_chars=1).upper()
    if target_char and st.button("Analyze positions"):
        positions = pattern_analyzer.character_positions(ciphertext, target_char)
        if positions:
            st.write(f"**Character '{target_char}' appears at positions:** {positions}")
            
            # Check for patterns in positions
            if len(positions) > 2:
                differences = [positions[i+1] - positions[i] for i in range(len(positions)-1)]
                st.write(f"**Differences between positions:** {differences}")
                
                # Check for regular intervals
                if len(set(differences)) == 1:
                    st.write(f"**Regular interval detected:** {differences[0]}")
                    st.write("This might indicate a periodic cipher!")

def educational_info_page():
    st.header("📚 Educational Information")
    
    cipher_info = st.selectbox(
        "Select cipher to learn about:",
        ["Kryptos Sculpture", "Caesar Cipher", "Vigenère Cipher", "Substitution Cipher", "Frequency Analysis", "Index of Coincidence"]
    )
    
    if cipher_info == "Kryptos Sculpture":
        st.subheader("🏛️ Kryptos Sculpture")
        st.markdown("""
        **Artist:** Jim Sanborn  
        **Location:** CIA Headquarters, Langley, Virginia, USA  
        **Installed:** 1990  
        **Description:** An encrypted sculpture containing four separate coded messages (K1, K2, K3, K4). The first three have been solved, but K4 remains one of the world's most famous unsolved ciphers.
        
        ---
        
        ### Solved Sections
        
        **K1 (SOLVED 1999):**
        *"BETWEEN SUBTLE SHADING AND THE ABSENCE OF LIGHT LIES THE NUANCE OF IQLUSION"*
        
        **K2 (SOLVED 1999):**
        *"IT WAS TOTALLY INVISIBLE HOWS THAT POSSIBLE ? THEY USED THE EARTHS MAGNETIC FIELD X THE INFORMATION WAS GATHERED AND TRANSMITTED UNDERGRUUND TO AN UNKNOWN LOCATION X DOES LANGLEY KNOW ABOUT THIS ? THEY SHOULD ITS BURIED OUT THERE SOMEWHERE X WHO KNOWS THE EXACT LOCATION ? ONLY WW THIS WAS HIS LAST MESSAGE X THIRTY EIGHT DEGREES FIFTY SEVEN MINUTES SIX POINT FIVE SECONDS NORTH SEVENTY SEVEN DEGREES EIGHT MINUTES FORTY FOUR SECONDS WEST X LAYER TWO"*
        
        **K3 (SOLVED 2010):**
        *"SLOWLY DESPARATLY SLOWLY THE REMAINS OF PASSAGE DEBRIS THAT ENCUMBERED THE LOWER PART OF THE DOORWAY WAS REMOVED WITH TREMBLING HANDS I MADE A TINY BREACH IN THE UPPER LEFT HAND CORNER AND THEN WIDENING THE HOLE A LITTLE I INSERTED THE CANDLE AND PEERED IN THE HOT AIR ESCAPING FROM THE CHAMBER CAUSED THE FLAME TO FLICKER BUT PRESENTLY DETAILS OF THE ROOM WITHIN EMERGED FROM THE MIST X CAN YOU SEE ANYTHING Q ?"*
        
        ### K4 - The Unsolved Mystery
        
        **Status:** UNSOLVED  
        **Length:** 97 characters  
        **Cipher Text:** `OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR`
        
        **Known Plaintext Segments:**
        - EASTNORTHEAST (positions 22-34)
        - BERLIN (positions 64-69)
        - CLOCK (positions 70-74)
        
        These clues were released by Jim Sanborn to assist codebreakers in solving the final section.
        
        ### Historical Context
        
        The sculpture was commissioned by the CIA to demonstrate the importance of intelligence gathering and the art of cryptography. It has inspired countless cryptographers, amateur codebreakers, and computer scientists to attempt solving K4. The first three sections were solved by NSA cryptanalyst David Stein, but K4 has resisted all attempts at solution for over three decades.
        """)
    
    elif cipher_info == "Caesar Cipher":
        st.subheader("🔄 Caesar Cipher")
        st.write("""
        **Description:** A substitution cipher where each letter is shifted by a fixed number of positions in the alphabet.
        
        **How it works:**
        - Choose a shift value (0-25)
        - Replace each letter with the letter that many positions ahead in the alphabet
        - Wrap around from Z to A
        
        **Example:** With shift 3, A→D, B→E, C→F, ..., X→A, Y→B, Z→C
        
        **Weaknesses:**
        - Only 25 possible keys (shifts)
        - Vulnerable to brute force attack
        - Frequency distribution remains the same (just shifted)
        
        **Famous use:** Named after Julius Caesar, who reportedly used it with a shift of 3.
        """)
    
    elif cipher_info == "Vigenère Cipher":
        st.subheader("🗝️ Vigenère Cipher")
        st.write("""
        **Description:** A polyalphabetic substitution cipher using a repeating keyword.
        
        **How it works:**
        - Choose a keyword (e.g., "KEY")
        - Repeat the keyword to match the message length
        - For each position, use Caesar cipher with shift = keyword letter position
        
        **Example:** 
        - Message: "HELLO"
        - Key: "KEYKE"
        - Shifts: K=10, E=4, Y=24, K=10, E=4
        - Result: "RIJVS"
        
        **Weaknesses:**
        - Key length can be determined using statistical analysis
        - Once key length is known, becomes multiple Caesar ciphers
        
        **Historical note:** Called "le chiffre indéchiffrable" (the indecipherable cipher) for 300 years.
        """)
    
    elif cipher_info == "Substitution Cipher":
        st.subheader("🔀 Substitution Cipher")
        st.write("""
        **Description:** Each letter of the alphabet is replaced with another letter according to a fixed mapping.
        
        **How it works:**
        - Create a mapping between alphabet letters (A→X, B→F, C→R, etc.)
        - Replace each letter in the message using this mapping
        
        **Example:**
        - Alphabet: ABCDEFGHIJKLMNOPQRSTUVWXYZ
        - Key:      XFRGHJKLMNOPQRSTUVWYZABCEI
        - "HELLO" → "KJOOR"
        
        **Strengths:**
        - 26! possible keys (huge number)
        - Much stronger than Caesar cipher
        
        **Weaknesses:**
        - Frequency analysis can reveal the mapping
        - Common letter patterns can be exploited
        
        **Breaking method:** Use frequency analysis to match cipher letters with common English letters.
        """)
    
    elif cipher_info == "Frequency Analysis":
        st.subheader("📊 Frequency Analysis")
        st.write("""
        **Description:** Statistical analysis of letter frequencies to break substitution ciphers.
        
        **English Letter Frequencies (approximate):**
        - Most common: E (12.7%), T (9.1%), A (8.2%), O (7.5%), I (7.0%), N (6.7%)
        - Least common: Z (0.1%), Q (0.1%), X (0.2%), J (0.2%), K (0.8%)
        
        **How to use:**
        1. Count frequency of each letter in ciphertext
        2. Match most frequent cipher letters with most frequent English letters
        3. Look for common patterns (THE, AND, ING, etc.)
        4. Iteratively refine the mapping
        
        **Bigrams and Trigrams:**
        - Common bigrams: TH, HE, IN, ER, AN
        - Common trigrams: THE, AND, ING, HER, HAT
        
        **Limitations:**
        - Doesn't work on polyalphabetic ciphers
        - Requires sufficient text length
        - Can be fooled by unusual text content
        """)
    
    elif cipher_info == "Index of Coincidence":
        st.subheader("🎯 Index of Coincidence")
        st.write("""
        **Description:** A statistical measure used to determine if a cipher is monoalphabetic or polyalphabetic.
        
        **Formula:** IC = Σ(nᵢ(nᵢ-1)) / (N(N-1))
        - nᵢ = frequency of letter i
        - N = total number of letters
        
        **Interpretation:**
        - **IC ≈ 0.067:** English text or monoalphabetic cipher
        - **IC ≈ 0.038:** Random text or strong polyalphabetic cipher
        - **IC between 0.038-0.067:** Weak polyalphabetic cipher
        
        **Applications:**
        - Distinguish between cipher types
        - Determine Vigenère key length
        - Assess cipher strength
        
        **Key Length Determination:**
        For Vigenère cipher, calculate IC for each column when text is arranged in rows of suspected key length.
        If IC values are high, the key length is likely correct.
        """)

# Helper functions
def score_english_text(text):
    """Score text based on English letter frequency"""
    if not text:
        return 0
    
    english_freq = {
        'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7, 'S': 6.3, 'H': 6.1,
        'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8, 'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2,
        'G': 2.0, 'Y': 2.0, 'P': 1.9, 'B': 1.3, 'V': 1.0, 'K': 0.8, 'J': 0.15, 'X': 0.15,
        'Q': 0.10, 'Z': 0.07
    }
    
    text_upper = text.upper()
    text_letters = [c for c in text_upper if c.isalpha()]
    
    if not text_letters:
        return 0
    
    score = 0
    for char in text_letters:
        score += english_freq.get(char, 0)
    
    return score / len(text_letters)

def calculate_index_of_coincidence(text):
    """Calculate Index of Coincidence for text"""
    text = ''.join(c.upper() for c in text if c.isalpha())
    n = len(text)
    
    if n < 2:
        return 0
    
    freq = Counter(text)
    ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
    return ic

def analyze_frequency_distribution(text):
    """Analyze how close frequency distribution is to English"""
    text = ''.join(c.upper() for c in text if c.isalpha())
    if not text:
        return 0
    
    freq = Counter(text)
    total = len(text)
    
    # Expected English frequencies
    english_freq = [12.7, 9.1, 8.2, 7.5, 7.0, 6.7, 6.3, 6.1, 6.0, 4.3, 4.0, 2.8, 2.8, 2.4, 2.4, 2.2, 2.0, 2.0, 1.9, 1.3, 1.0, 0.8, 0.15, 0.15, 0.10, 0.07]
    
    # Actual frequencies
    actual_freq = []
    for i in range(26):
        char = chr(ord('A') + i)
        actual_freq.append((freq.get(char, 0) / total) * 100)
    
    # Calculate chi-squared statistic
    chi_squared = sum((actual - expected) ** 2 / expected for actual, expected in zip(actual_freq, english_freq) if expected > 0)
    
    # Convert to a score (lower chi-squared = higher score)
    return max(0, 1000 - chi_squared) / 1000

if __name__ == "__main__":
    main()
