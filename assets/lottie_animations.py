"""
Lottie Animations Module

Provides Lottie animation support for the MalwareShield Pro application.
Since we cannot use external binary files, this module provides fallback
animated text and emoji-based indicators for scanning states.
"""

import streamlit as st
import time
import threading
from typing import Dict, Any, Optional

def get_lottie_animation(animation_type: str) -> Optional[Dict[str, Any]]:
    """Get Lottie animation data for specified type
    
    Args:
        animation_type: Type of animation ('scanning', 'virustotal', 'shield', 'loading')
        
    Returns:
        dict: Animation configuration or None if not available
    """
    # Since we can't use actual Lottie files, we'll return configuration
    # for our text-based animations
    animations = {
        'scanning': {
            'type': 'scanning',
            'frames': ['🔍', '🔎', '🔍', '🔎'],
            'message': 'Scanning file for threats...',
            'color': '#00aaff'
        },
        'virustotal': {
            'type': 'virustotal', 
            'frames': ['🌐', '🔄', '📡', '🔄'],
            'message': 'Analyzing with VirusTotal...',
            'color': '#1e88e5'
        },
        'shield': {
            'type': 'shield',
            'frames': ['🛡️', '⚡', '🛡️', '⚡'],
            'message': 'Protection active',
            'color': '#4caf50'
        },
        'loading': {
            'type': 'loading',
            'frames': ['⏳', '⌛', '⏳', '⌛'],
            'message': 'Processing...',
            'color': '#ff9800'
        },
        'success': {
            'type': 'success',
            'frames': ['✅', '🎉', '✅', '🎉'],
            'message': 'Scan completed successfully!',
            'color': '#4caf50'
        },
        'warning': {
            'type': 'warning',
            'frames': ['⚠️', '🚨', '⚠️', '🚨'],
            'message': 'Threats detected!',
            'color': '#ff5722'
        },
        'error': {
            'type': 'error',
            'frames': ['❌', '💥', '❌', '💥'],
            'message': 'Scan failed',
            'color': '#f44336'
        }
    }
    
    return animations.get(animation_type)

def display_lottie(animation_data: Optional[Dict[str, Any]], key: str, height: int = 200) -> None:
    """Display animated content in place of Lottie animation
    
    Args:
        animation_data: Animation configuration
        key: Unique key for the animation widget
        height: Height of animation area (unused in text version)
    """
    if not animation_data:
        st.info("🔍 Processing...")
        return
    
    # Create animation container
    animation_container = st.empty()
    
    # Get animation properties
    frames = animation_data.get('frames', ['⏳'])
    message = animation_data.get('message', 'Processing...')
    animation_type = animation_data.get('type', 'loading')
    
    # Display static version for now
    # In a real implementation, you could use st.empty() with a loop
    # to create animated effects, but for simplicity we'll show static
    
    if animation_type == 'scanning':
        animation_container.markdown(
            f"""
            <div style="text-align: center; padding: 20px;">
                <div style="font-size: 3em; margin-bottom: 10px;">🔍</div>
                <div style="font-size: 1.2em; color: #00aaff;">{message}</div>
                <div style="margin-top: 10px;">
                    <div style="width: 100%; background-color: #f0f0f0; border-radius: 10px;">
                        <div style="width: 60%; height: 4px; background-color: #00aaff; border-radius: 10px; animation: pulse 2s infinite;"></div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
    elif animation_type == 'virustotal':
        animation_container.markdown(
            f"""
            <div style="text-align: center; padding: 20px;">
                <div style="font-size: 3em; margin-bottom: 10px;">🌐</div>
                <div style="font-size: 1.2em; color: #1e88e5;">{message}</div>
                <div style="margin-top: 10px; font-size: 0.9em; color: #666;">
                    Connecting to VirusTotal servers...
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
    elif animation_type == 'shield':
        animation_container.markdown(
            f"""
            <div style="text-align: center; padding: 20px;">
                <div style="font-size: 3em; margin-bottom: 10px;">🛡️</div>
                <div style="font-size: 1.2em; color: #4caf50;">{message}</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    elif animation_type == 'success':
        animation_container.markdown(
            f"""
            <div style="text-align: center; padding: 20px;">
                <div style="font-size: 3em; margin-bottom: 10px;">✅</div>
                <div style="font-size: 1.2em; color: #4caf50;">{message}</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    elif animation_type == 'warning':
        animation_container.markdown(
            f"""
            <div style="text-align: center; padding: 20px;">
                <div style="font-size: 3em; margin-bottom: 10px;">⚠️</div>
                <div style="font-size: 1.2em; color: #ff5722;">{message}</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    elif animation_type == 'error':
        animation_container.markdown(
            f"""
            <div style="text-align: center; padding: 20px;">
                <div style="font-size: 3em; margin-bottom: 10px;">❌</div>
                <div style="font-size: 1.2em; color: #f44336;">{message}</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    else:
        # Default loading animation
        animation_container.markdown(
            f"""
            <div style="text-align: center; padding: 20px;">
                <div style="font-size: 3em; margin-bottom: 10px;">⏳</div>
                <div style="font-size: 1.2em; color: #ff9800;">{message}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

def display_animated_progress(message: str = "Scanning...", duration: int = 3) -> None:
    """Display an animated progress indicator
    
    Args:
        message: Message to display
        duration: Duration in seconds
    """
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    frames = ['🔍', '🔎', '🔍', '🔎']
    
    for i in range(duration * 10):  # 10 updates per second
        frame_idx = (i // 3) % len(frames)
        progress = (i + 1) / (duration * 10)
        
        status_text.text(f"{frames[frame_idx]} {message}")
        progress_bar.progress(progress)
        
        time.sleep(0.1)
    
    progress_bar.progress(1.0)
    status_text.text(f"✅ {message} Complete!")

def show_scanning_animation(scan_type: str = "local") -> None:
    """Show appropriate scanning animation based on scan type
    
    Args:
        scan_type: Type of scan ('local', 'virustotal')
    """
    if scan_type == "virustotal":
        animation_data = get_lottie_animation("virustotal")
        display_lottie(animation_data, "vt_scan")
    else:
        animation_data = get_lottie_animation("scanning")
        display_lottie(animation_data, "local_scan")

def show_result_animation(threat_level: str) -> None:
    """Show result animation based on threat level
    
    Args:
        threat_level: Detected threat level
    """
    if threat_level in ['CLEAN', 'LOW']:
        animation_data = get_lottie_animation("success")
        display_lottie(animation_data, "result_success")
    elif threat_level in ['MEDIUM']:
        animation_data = get_lottie_animation("warning")
        display_lottie(animation_data, "result_warning")
    elif threat_level in ['HIGH', 'CRITICAL']:
        animation_data = get_lottie_animation("error")
        display_lottie(animation_data, "result_error")
    else:
        animation_data = get_lottie_animation("loading")
        display_lottie(animation_data, "result_unknown")

# Additional utility functions for enhanced animations

def create_pulse_effect(element_id: str, color: str = "#00aaff") -> str:
    """Create CSS for pulse effect
    
    Args:
        element_id: CSS element ID
        color: Pulse color
        
    Returns:
        str: CSS animation code
    """
    return f"""
    <style>
    #{element_id} {{
        animation: pulse-{element_id} 2s infinite;
    }}
    
    @keyframes pulse-{element_id} {{
        0% {{ box-shadow: 0 0 0 0 {color}40; }}
        70% {{ box-shadow: 0 0 0 10px {color}00; }}
        100% {{ box-shadow: 0 0 0 0 {color}00; }}
    }}
    </style>
    """

def create_spinner_effect(element_id: str) -> str:
    """Create CSS for spinner effect
    
    Args:
        element_id: CSS element ID
        
    Returns:
        str: CSS animation code
    """
    return f"""
    <style>
    #{element_id} {{
        animation: spin-{element_id} 2s linear infinite;
    }}
    
    @keyframes spin-{element_id} {{
        0% {{ transform: rotate(0deg); }}
        100% {{ transform: rotate(360deg); }}
    }}
    </style>
    """

def display_scanning_status(status: str, progress: float = None) -> None:
    """Display scanning status with appropriate visual indicators
    
    Args:
        status: Current status message
        progress: Progress value (0.0 to 1.0) if available
    """
    col1, col2 = st.columns([1, 4])
    
    with col1:
        # Rotate through scanning icons
        icons = ['🔍', '🔎', '🔍', '🔎']
        icon_idx = int(time.time() * 2) % len(icons)  # Change every 0.5 seconds
        st.markdown(f"<div style='font-size: 2em; text-align: center;'>{icons[icon_idx]}</div>", unsafe_allow_html=True)
    
    with col2:
        st.write(f"**{status}**")
        if progress is not None:
            st.progress(progress)

def display_threat_indicator(threat_level: str) -> None:
    """Display threat level with appropriate visual indicator
    
    Args:
        threat_level: Threat level string
    """
    indicators = {
        'CLEAN': ('✅', '#4caf50', 'File is clean'),
        'LOW': ('⚠️', '#ff9800', 'Low risk detected'),
        'MEDIUM': ('🚨', '#ff5722', 'Medium threat level'),
        'HIGH': ('🔴', '#f44336', 'High threat detected'),
        'CRITICAL': ('☠️', '#d32f2f', 'Critical threat!')
    }
    
    icon, color, message = indicators.get(threat_level, ('❓', '#666', 'Unknown threat level'))
    
    st.markdown(
        f"""
        <div style="text-align: center; padding: 15px; border: 2px solid {color}; border-radius: 10px; background-color: {color}20;">
            <div style="font-size: 2.5em; margin-bottom: 5px;">{icon}</div>
            <div style="font-size: 1.3em; font-weight: bold; color: {color};">{threat_level}</div>
            <div style="font-size: 1em; color: {color};">{message}</div>
        </div>
        """,
        unsafe_allow_html=True
    )
