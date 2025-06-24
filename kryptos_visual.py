"""
Enhanced visual components for Kryptos cipher analysis
"""

import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import numpy as np
import pandas as pd

class KryptosVisualizer:
    """Visual components for Kryptos analysis"""
    
    def __init__(self):
        self.color_scheme = {
            'known': '#ff6b6b',
            'unknown': '#95a5a6',
            'correct': '#27ae60',
            'incorrect': '#e74c3c',
            'uncertain': '#f39c12'
        }
    
    def create_cipher_heatmap(self, ciphertext, known_positions=None):
        """Create a heatmap visualization of the cipher"""
        if known_positions is None:
            known_positions = {}
            
        # Create grid (10 columns)
        rows = (len(ciphertext) + 9) // 10
        grid = np.zeros((rows, 10))
        char_grid = [['' for _ in range(10)] for _ in range(rows)]
        
        for i, char in enumerate(ciphertext):
            row, col = i // 10, i % 10
            grid[row][col] = 1 if i in known_positions else 0
            char_grid[row][col] = char
        
        # Create heatmap
        fig = go.Figure(data=go.Heatmap(
            z=grid,
            text=char_grid,
            texttemplate="%{text}",
            textfont={"size": 12, "color": "white"},
            colorscale=[[0, self.color_scheme['unknown']], [1, self.color_scheme['known']]],
            showscale=False,
            hovertemplate='Position: %{x},%{y}<br>Character: %{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title="K4 Cipher Grid - Red = Known Plaintext",
            xaxis_title="Column",
            yaxis_title="Row",
            height=300,
            font=dict(family="monospace")
        )
        
        return fig
    
    def create_frequency_comparison(self, cipher_freq, english_freq):
        """Create frequency comparison chart"""
        # Prepare data
        chars = list(set(cipher_freq.keys()) | set(english_freq.keys()))
        cipher_values = [cipher_freq.get(c, 0) for c in chars]
        english_values = [english_freq.get(c, 0) for c in chars]
        
        fig = go.Figure()
        
        fig.add_trace(go.Bar(
            name='K4 Frequency',
            x=chars,
            y=cipher_values,
            marker_color=self.color_scheme['known']
        ))
        
        fig.add_trace(go.Bar(
            name='English Frequency',
            x=chars,
            y=english_values,
            marker_color=self.color_scheme['unknown'],
            opacity=0.7
        ))
        
        fig.update_layout(
            title="Frequency Comparison: K4 vs English",
            xaxis_title="Letters",
            yaxis_title="Frequency (%)",
            barmode='group'
        )
        
        return fig
    
    def create_position_analysis(self, text_length, known_positions):
        """Create position analysis visualization"""
        positions = list(range(text_length))
        is_known = [1 if i in known_positions else 0 for i in positions]
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=positions,
            y=is_known,
            mode='markers',
            marker=dict(
                size=8,
                color=[self.color_scheme['known'] if k else self.color_scheme['unknown'] for k in is_known]
            ),
            name='Position Status'
        ))
        
        # Add annotations for known segments
        segments = [
            (21, 33, 'EASTNORTHEAST'),
            (63, 68, 'BERLIN'),
            (69, 73, 'CLOCK')
        ]
        
        for start, end, label in segments:
            fig.add_vrect(
                x0=start, x1=end,
                fillcolor=self.color_scheme['known'],
                opacity=0.2,
                annotation_text=label,
                annotation_position="top left"
            )
        
        fig.update_layout(
            title="Known Plaintext Positions in K4",
            xaxis_title="Character Position",
            yaxis_title="Known (1) / Unknown (0)",
            height=300
        )
        
        return fig
    
    def create_key_analysis_chart(self, key_analysis_results):
        """Create key length analysis chart"""
        if not key_analysis_results:
            return None
            
        key_lengths = list(key_analysis_results.keys())
        confidences = [result['confidence'] for result in key_analysis_results.values()]
        
        fig = go.Figure(data=go.Bar(
            x=key_lengths,
            y=confidences,
            marker_color=[self.color_scheme['correct'] if c > 0.5 else 
                         self.color_scheme['uncertain'] if c > 0.2 else 
                         self.color_scheme['incorrect'] for c in confidences]
        ))
        
        fig.update_layout(
            title="Key Length Analysis - Confidence Scores",
            xaxis_title="Key Length",
            yaxis_title="Confidence Score",
            height=400
        )
        
        return fig
    
    def create_decryption_comparison(self, original, decrypted, known_positions):
        """Create visual comparison of original vs decrypted"""
        comparison_data = []
        
        for i, (orig_char, decr_char) in enumerate(zip(original, decrypted)):
            status = 'unknown'
            if i in known_positions:
                status = 'correct' if decr_char == known_positions[i] else 'incorrect'
            
            comparison_data.append({
                'Position': i,
                'Original': orig_char,
                'Decrypted': decr_char,
                'Status': status
            })
        
        df = pd.DataFrame(comparison_data)
        
        # Create subplot
        fig = make_subplots(
            rows=2, cols=1,
            subplot_titles=('Original Ciphertext', 'Decrypted Result'),
            vertical_spacing=0.1
        )
        
        # Original text
        fig.add_trace(
            go.Scatter(
                x=df['Position'],
                y=[1] * len(df),
                mode='markers+text',
                text=df['Original'],
                textposition="middle center",
                marker=dict(
                    size=20,
                    color=[self.color_scheme['known'] if i in known_positions else self.color_scheme['unknown'] 
                          for i in df['Position']]
                ),
                showlegend=False
            ),
            row=1, col=1
        )
        
        # Decrypted text
        colors = [self.color_scheme[status] for status in df['Status']]
        fig.add_trace(
            go.Scatter(
                x=df['Position'],
                y=[1] * len(df),
                mode='markers+text',
                text=df['Decrypted'],
                textposition="middle center",
                marker=dict(size=20, color=colors),
                showlegend=False
            ),
            row=2, col=1
        )
        
        fig.update_layout(
            title="Cipher vs Decryption Comparison",
            height=300,
            showlegend=False
        )
        
        # Hide y-axes
        fig.update_yaxes(visible=False)
        
        return fig

def create_interactive_cipher_grid(ciphertext, known_positions=None):
    """Create an interactive cipher grid with hover information"""
    if known_positions is None:
        known_positions = {}
    
    # Create grid data
    grid_data = []
    for i, char in enumerate(ciphertext):
        row = i // 10
        col = i % 10
        is_known = i in known_positions
        plain_char = known_positions.get(i, '?')
        
        grid_data.append({
            'row': row,
            'col': col,
            'position': i,
            'cipher_char': char,
            'plain_char': plain_char if is_known else '?',
            'is_known': is_known,
            'segment': get_segment_name(i)
        })
    
    df = pd.DataFrame(grid_data)
    
    # Create scatter plot to simulate grid
    fig = px.scatter(
        df, 
        x='col', 
        y='row',
        color='is_known',
        text='cipher_char',
        hover_data=['position', 'cipher_char', 'plain_char', 'segment'],
        color_discrete_map={True: '#ff6b6b', False: '#95a5a6'},
        title="Interactive K4 Cipher Grid"
    )
    
    fig.update_traces(
        textposition="middle center",
        marker=dict(size=30, line=dict(width=1, color='black'))
    )
    
    # Reverse y-axis to match reading order
    fig.update_yaxes(autorange="reversed")
    
    fig.update_layout(
        showlegend=False,
        height=400,
        font=dict(family="monospace", size=12)
    )
    
    return fig

def get_segment_name(position):
    """Get the segment name for a given position"""
    if 21 <= position <= 33:
        return 'EASTNORTHEAST'
    elif 63 <= position <= 68:
        return 'BERLIN'
    elif 69 <= position <= 73:
        return 'CLOCK'
    else:
        return 'Unknown'