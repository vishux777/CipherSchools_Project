"""
Lottie Animation Support for MalwareShield Pro
Provides animated feedback for scanning operations

Built with 🛡️ by [Vishwas]
"""

import streamlit as st
from typing import Optional, Dict, Any

def get_lottie_animation(animation_type: str) -> Optional[Dict[str, Any]]:
    """
    Get Lottie animation data for different states
    
    Args:
        animation_type: Type of animation ('scanning', 'success', 'warning', 'error')
        
    Returns:
        Animation data dictionary or None if not available
    """
    # Since we can't include actual Lottie files, we'll use simple CSS animations
    # This is a placeholder that returns None to trigger fallback behavior
    return None

def display_lottie(animation_data: Optional[Dict], key: str):
    """
    Display Lottie animation or fallback
    
    Args:
        animation_data: Animation data (None for fallback)
        key: Unique key for the animation
    """
    if animation_data is None:
        # Fallback to simple CSS animation with mobile optimization
        st.markdown("""
        <div style="text-align: center; padding: 20px;">
            <div class="scanning-animation">
                <div class="spinner"></div>
                <p style="margin-top: 15px; color: #00aaff;">🔍 Scanning in progress...</p>
            </div>
        </div>
        
        <style>
        .scanning-animation {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }
        
        .spinner {
            width: 40px;
            height: 40px;
            border: 4px solid #f3f3f3;
            border-top: 4px solid #00aaff;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        @media (max-width: 768px) {
            .spinner {
                width: 30px;
                height: 30px;
                border-width: 3px;
            }
        }
        </style>
        """, unsafe_allow_html=True)
    else:
        # Would display actual Lottie animation here
        st.info("🔍 Scanning in progress...")

def show_result_animation(threat_level: str):
    """
    Show result animation based on threat level with mobile optimization
    
    Args:
        threat_level: Detected threat level
    """
    animations = {
        'CRITICAL': {
            'icon': '🚨',
            'color': '#DC143C',
            'message': 'Critical threat detected!',
            'animation': 'pulse-critical'
        },
        'HIGH': {
            'icon': '⚠️',
            'color': '#FF6347',
            'message': 'High threat detected!',
            'animation': 'pulse-high'
        },
        'MEDIUM': {
            'icon': '⚡',
            'color': '#FFA500',
            'message': 'Medium threat detected!',
            'animation': 'pulse-medium'
        },
        'LOW': {
            'icon': '🔍',
            'color': '#32CD32',
            'message': 'Low threat detected',
            'animation': 'pulse-low'
        },
        'CLEAN': {
            'icon': '✅',
            'color': '#32CD32',
            'message': 'File appears clean',
            'animation': 'pulse-clean'
        }
    }
    
    config = animations.get(threat_level, animations['CLEAN'])
    
    st.markdown(f"""
    <div style="text-align: center; padding: 20px;">
        <div class="result-animation">
            <div class="result-icon {config['animation']}" style="color: {config['color']}; font-size: 48px;">
                {config['icon']}
            </div>
            <p style="margin-top: 15px; color: {config['color']}; font-weight: bold; font-size: 18px;">
                {config['message']}
            </p>
        </div>
    </div>
    
    <style>
    .result-animation {{
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
    }}
    
    .result-icon {{
        display: inline-block;
        animation-duration: 2s;
        animation-iteration-count: 3;
    }}
    
    .pulse-critical {{
        animation-name: pulse-critical;
    }}
    
    .pulse-high {{
        animation-name: pulse-high;
    }}
    
    .pulse-medium {{
        animation-name: pulse-medium;
    }}
    
    .pulse-low {{
        animation-name: pulse-low;
    }}
    
    .pulse-clean {{
        animation-name: pulse-clean;
    }}
    
    @keyframes pulse-critical {{
        0%, 100% {{ transform: scale(1); }}
        25% {{ transform: scale(1.2); }}
        50% {{ transform: scale(1); }}
        75% {{ transform: scale(1.2); }}
    }}
    
    @keyframes pulse-high {{
        0%, 100% {{ transform: scale(1); }}
        50% {{ transform: scale(1.1); }}
    }}
    
    @keyframes pulse-medium {{
        0%, 100% {{ transform: scale(1); }}
        50% {{ transform: scale(1.05); }}
    }}
    
    @keyframes pulse-low {{
        0%, 100% {{ transform: scale(1); }}
        50% {{ transform: scale(1.02); }}
    }}
    
    @keyframes pulse-clean {{
        0%, 100% {{ transform: scale(1); }}
        50% {{ transform: scale(1.05); }}
    }}
    
    @media (max-width: 768px) {{
        .result-icon {{
            font-size: 36px;
        }}
        
        .result-animation p {{
            font-size: 16px;
        }}
    }}
    </style>
    """, unsafe_allow_html=True)

def show_loading_animation(message: str = "Processing..."):
    """
    Show loading animation with custom message and mobile optimization
    
    Args:
        message: Custom loading message
    """
    st.markdown(f"""
    <div style="text-align: center; padding: 20px;">
        <div class="loading-animation">
            <div class="loading-dots">
                <span></span>
                <span></span>
                <span></span>
            </div>
            <p style="margin-top: 15px; color: #00aaff;">{message}</p>
        </div>
    </div>
    
    <style>
    .loading-animation {{
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
    }}
    
    .loading-dots {{
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
    }}
    
    .loading-dots span {{
        width: 12px;
        height: 12px;
        border-radius: 50%;
        background-color: #00aaff;
        animation: loading-bounce 1.4s infinite ease-in-out both;
    }}
    
    .loading-dots span:nth-child(1) {{
        animation-delay: -0.32s;
    }}
    
    .loading-dots span:nth-child(2) {{
        animation-delay: -0.16s;
    }}
    
    @keyframes loading-bounce {{
        0%, 80%, 100% {{
            transform: scale(0);
        }}
        40% {{
            transform: scale(1);
        }}
    }}
    
    @media (max-width: 768px) {{
        .loading-dots span {{
            width: 10px;
            height: 10px;
        }}
    }}
    </style>
    """, unsafe_allow_html=True)
