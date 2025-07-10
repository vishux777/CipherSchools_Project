"""
Report Generation Module
Generate comprehensive malware analysis reports
"""

import json
import csv
import io
import base64
from datetime import datetime
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

class ReportGenerator:
    """
    Generate comprehensive analysis reports in various formats
    """
    
    def __init__(self):
        """Initialize the report generator"""
        self.report_template = {
            'version': '1.0',
            'generator': 'MalwareShield Pro',
            'created_by': 'vishux777'
        }
    
    def generate_comprehensive_report(self, analysis_results):
        """
        Generate a comprehensive analysis report
        
        Args:
            analysis_results (dict): Complete analysis results
            
        Returns:
            dict: Formatted report
        """
        try:
            report = {
                **self.report_template,
                'report_id': self._generate_report_id(),
                'generated_at': datetime.now().isoformat(),
                'executive_summary': self._generate_executive_summary(analysis_results),
                'file_information': self._extract_file_information(analysis_results),
                'threat_assessment': self._format_threat_assessment(analysis_results),
                'technical_analysis': self._format_technical_analysis(analysis_results),
                'indicators_of_compromise': self._extract_iocs(analysis_results),
                'recommendations': self._generate_recommendations(analysis_results),
                'analysis_metadata': self._extract_analysis_metadata(analysis_results)
            }
            
            return report
        
        except Exception as e:
            return {
                'error': f"Failed to generate report: {str(e)}",
                'partial_data': analysis_results
            }
    
    def _generate_report_id(self):
        """Generate unique report ID"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"MSP_{timestamp}"
    
    def _generate_executive_summary(self, results):
        """Generate executive summary"""
        threat_assessment = results.get('threat_assessment', {})
        
        summary = {
            'threat_level': threat_assessment.get('level', 'Unknown'),
            'risk_score': threat_assessment.get('score', 0),
            'key_findings': [],
            'immediate_actions': []
        }
        
        # Extract key findings
        if threat_assessment.get('reasons'):
            summary['key_findings'] = threat_assessment['reasons'][:5]  # Top 5 findings
        
        # Generate immediate actions based on threat level
        threat_level = threat_assessment.get('level', 'LOW')
        if threat_level == 'CRITICAL':
            summary['immediate_actions'] = [
                "Do not execute this file",
                "Isolate the file immediately",
                "Perform full system scan",
                "Submit to security vendors for analysis"
            ]
        elif threat_level == 'HIGH':
            summary['immediate_actions'] = [
                "Exercise extreme caution",
                "Analyze in controlled environment",
                "Verify file source",
                "Consider additional analysis"
            ]
        elif threat_level == 'MEDIUM':
            summary['immediate_actions'] = [
                "Verify file source and integrity",
                "Consider additional scanning",
                "Monitor for suspicious behavior"
            ]
        else:
            summary['immediate_actions'] = [
                "File appears safe but remain cautious",
                "Regular monitoring recommended"
            ]
        
        return summary
    
    def _extract_file_information(self, results):
        """Extract file information for report"""
        file_info = {
            'filename': results.get('filename', 'Unknown'),
            'file_size': results.get('file_size', 0),
            'file_size_formatted': self._format_file_size(results.get('file_size', 0)),
            'analysis_time': results.get('analysis_time', ''),
            'analysis_duration': results.get('analysis_duration', 0)
        }
        
        # Add hash information
        if 'hashes' in results:
            file_info['hashes'] = results['hashes']
        
        # Add file signature
        if 'patterns' in results and 'file_signature' in results['patterns']:
            file_info['file_signature'] = results['patterns']['file_signature']
        
        return file_info
    
    def _format_file_size(self, size_bytes):
        """Format file size in human readable format"""
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024
            i += 1
        
        return f"{size_bytes:.2f} {size_names[i]}"
    
    def _format_threat_assessment(self, results):
        """Format threat assessment for report"""
        threat_assessment = results.get('threat_assessment', {})
        
        formatted = {
            'overall_threat_level': threat_assessment.get('level', 'Unknown'),
            'risk_score': threat_assessment.get('score', 0),
            'confidence_level': threat_assessment.get('confidence', 'Unknown'),
            'threat_indicators': threat_assessment.get('reasons', []),
            'recommendation': threat_assessment.get('recommendation', ''),
            'risk_breakdown': self._calculate_risk_breakdown(results)
        }
        
        return formatted
    
    def _calculate_risk_breakdown(self, results):
        """Calculate risk breakdown by category"""
        breakdown = {
            'entropy_risk': 0,
            'pattern_risk': 0,
            'behavioral_risk': 0,
            'metadata_risk': 0,
            'string_risk': 0
        }
        
        # Entropy risk
        if 'entropy' in results:
            entropy = results['entropy'].get('overall_entropy', 0)
            if entropy > 7.5:
                breakdown['entropy_risk'] = 30
            elif entropy > 7.0:
                breakdown['entropy_risk'] = 15
        
        # Pattern risk
        if 'patterns' in results:
            patterns = results['patterns']
            if patterns.get('suspicious_apis'):
                breakdown['pattern_risk'] += 20
            if patterns.get('crypto_indicators'):
                breakdown['pattern_risk'] += 15
            if patterns.get('network_indicators'):
                breakdown['pattern_risk'] += 10
        
        # Behavioral risk
        if 'behavioral' in results:
            behavioral_score = results['behavioral'].get('score', 0)
            breakdown['behavioral_risk'] = min(behavioral_score, 30)
        
        # Metadata risk
        if 'metadata' in results:
            metadata = results['metadata']
            if metadata.get('filename_analysis', {}).get('suspicious_extension'):
                breakdown['metadata_risk'] += 10
            if metadata.get('filename_analysis', {}).get('double_extension'):
                breakdown['metadata_risk'] += 15
        
        # String risk
        if 'strings' in results:
            strings = results['strings']
            if strings.get('interesting_strings', {}).get('suspicious_keywords'):
                breakdown['string_risk'] += 15
        
        return breakdown
    
    def _format_technical_analysis(self, results):
        """Format technical analysis details"""
        technical = {}
        
        # Entropy analysis
        if 'entropy' in results:
            technical['entropy_analysis'] = {
                'overall_entropy': results['entropy'].get('overall_entropy', 0),
                'entropy_assessment': results['entropy'].get('assessment', {}),
                'high_entropy_sections': len(results['entropy'].get('high_entropy_sections', [])),
                'entropy_variance': results['entropy'].get('entropy_variance', 0)
            }
        
        # String analysis
        if 'strings' in results:
            string_data = results['strings']
            technical['string_analysis'] = {
                'total_strings': string_data.get('total_strings', 0),
                'interesting_strings_count': sum(
                    len(strings) for strings in string_data.get('interesting_strings', {}).values()
                ),
                'string_categories': list(string_data.get('interesting_strings', {}).keys())
            }
        
        # Pattern analysis
        if 'patterns' in results:
            pattern_data = results['patterns']
            technical['pattern_analysis'] = {
                'total_patterns': pattern_data.get('pattern_statistics', {}).get('total_patterns', 0),
                'categories_detected': pattern_data.get('pattern_statistics', {}).get('categories_detected', 0),
                'most_common_category': pattern_data.get('pattern_statistics', {}).get('most_common_category', None)
            }
        
        # Behavioral analysis
        if 'behavioral' in results:
            behavioral_data = results['behavioral']
            technical['behavioral_analysis'] = {
                'behavioral_score': behavioral_data.get('score', 0),
                'risk_level': behavioral_data.get('risk_level', 'LOW'),
                'indicator_categories': list(behavioral_data.get('indicators', {}).keys())
            }
        
        return technical
    
    def _extract_iocs(self, results):
        """Extract Indicators of Compromise"""
        iocs = {
            'file_hashes': {},
            'network_indicators': [],
            'file_indicators': [],
            'registry_indicators': [],
            'behavioral_indicators': []
        }
        
        # File hashes
        if 'hashes' in results:
            iocs['file_hashes'] = results['hashes']
        
        # Network indicators
        if 'strings' in results:
            interesting_strings = results['strings'].get('interesting_strings', {})
            iocs['network_indicators'].extend(interesting_strings.get('urls', []))
            iocs['network_indicators'].extend(interesting_strings.get('ip_addresses', []))
            iocs['network_indicators'].extend(interesting_strings.get('emails', []))
        
        # File indicators
        if 'strings' in results:
            interesting_strings = results['strings'].get('interesting_strings', {})
            iocs['file_indicators'].extend(interesting_strings.get('file_paths', []))
        
        # Registry indicators
        if 'strings' in results:
            interesting_strings = results['strings'].get('interesting_strings', {})
            iocs['registry_indicators'].extend(interesting_strings.get('registry_keys', []))
        
        # Behavioral indicators
        if 'behavioral' in results:
            behavioral_indicators = results['behavioral'].get('indicators', {})
            for category, indicators in behavioral_indicators.items():
                iocs['behavioral_indicators'].extend(indicators)
        
        return iocs
    
    def _generate_recommendations(self, results):
        """Generate security recommendations"""
        threat_level = results.get('threat_assessment', {}).get('level', 'LOW')
        
        recommendations = {
            'immediate_actions': [],
            'investigation_steps': [],
            'prevention_measures': [],
            'monitoring_recommendations': []
        }
        
        # Immediate actions based on threat level
        if threat_level == 'CRITICAL':
            recommendations['immediate_actions'] = [
                "Immediately quarantine the file",
                "Do not execute under any circumstances",
                "Perform full system scan if file was executed",
                "Submit to security vendors for analysis",
                "Check for lateral movement if on network"
            ]
        elif threat_level == 'HIGH':
            recommendations['immediate_actions'] = [
                "Quarantine the file for analysis",
                "Verify file source and distribution method",
                "Analyze in isolated environment only",
                "Check for similar files on system"
            ]
        elif threat_level == 'MEDIUM':
            recommendations['immediate_actions'] = [
                "Verify file authenticity and source",
                "Consider additional scanning with multiple engines",
                "Monitor system behavior if file was executed"
            ]
        
        # Investigation steps
        recommendations['investigation_steps'] = [
            "Analyze file in sandbox environment",
            "Check file reputation in threat intelligence feeds",
            "Examine file metadata and creation timestamps",
            "Investigate file distribution method",
            "Check for similar files or variants"
        ]
        
        # Prevention measures
        recommendations['prevention_measures'] = [
            "Implement application whitelisting",
            "Deploy endpoint detection and response (EDR)",
            "Regular security awareness training",
            "Keep security solutions updated",
            "Implement email security filtering"
        ]
        
        # Monitoring recommendations
        recommendations['monitoring_recommendations'] = [
            "Monitor for file hash IOCs",
            "Watch for behavioral patterns identified",
            "Monitor network connections to identified IPs/domains",
            "Set up alerts for similar file types",
            "Regular threat hunting activities"
        ]
        
        return recommendations
    
    def _extract_analysis_metadata(self, results):
        """Extract analysis metadata"""
        metadata = {
            'analysis_modules_used': results.get('modules_run', []),
            'analysis_errors': results.get('errors', []),
            'analysis_duration': results.get('analysis_duration', 0),
            'analysis_timestamp': results.get('analysis_time', ''),
            'total_indicators': self._count_total_indicators(results)
        }
        
        return metadata
    
    def _count_total_indicators(self, results):
        """Count total indicators found"""
        count = 0
        
        # Count patterns
        if 'patterns' in results:
            patterns = results['patterns']
            count += sum(len(matches) for matches in patterns.values() if isinstance(matches, list))
        
        # Count behavioral indicators
        if 'behavioral' in results:
            behavioral = results['behavioral'].get('indicators', {})
            count += sum(len(indicators) for indicators in behavioral.values() if isinstance(indicators, list))
        
        # Count interesting strings
        if 'strings' in results:
            interesting_strings = results['strings'].get('interesting_strings', {})
            count += sum(len(strings) for strings in interesting_strings.values() if isinstance(strings, list))
        
        return count
    
    def export_json(self, analysis_results, include_raw_data=False):
        """
        Export analysis results as JSON
        
        Args:
            analysis_results (dict): Analysis results
            include_raw_data (bool): Whether to include raw analysis data
            
        Returns:
            str: JSON formatted report
        """
        try:
            if include_raw_data:
                export_data = analysis_results
            else:
                export_data = self.generate_comprehensive_report(analysis_results)
            
            return json.dumps(export_data, indent=2, default=str)
        
        except Exception as e:
            return json.dumps({
                'error': f"Failed to export JSON: {str(e)}",
                'timestamp': datetime.now().isoformat()
            }, indent=2)
    
    def export_csv(self, analysis_results):
        """
        Export key analysis results as CSV
        
        Args:
            analysis_results (dict): Analysis results
            
        Returns:
            str: CSV formatted data
        """
        try:
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow(['Category', 'Indicator', 'Value', 'Risk Level'])
            
            # File information
            writer.writerow(['File Info', 'Filename', analysis_results.get('filename', ''), 'Info'])
            writer.writerow(['File Info', 'Size', analysis_results.get('file_size', 0), 'Info'])
            
            # Threat assessment
            threat_assessment = analysis_results.get('threat_assessment', {})
            writer.writerow(['Threat', 'Level', threat_assessment.get('level', ''), 'Assessment'])
            writer.writerow(['Threat', 'Score', threat_assessment.get('score', 0), 'Assessment'])
            
            # Hashes
            if 'hashes' in analysis_results:
                for hash_type, hash_value in analysis_results['hashes'].items():
                    writer.writerow(['Hash', hash_type.upper(), hash_value, 'IOC'])
            
            # Patterns
            if 'patterns' in analysis_results:
                patterns = analysis_results['patterns']
                for category, matches in patterns.items():
                    if isinstance(matches, list):
                        for match in matches:
                            writer.writerow(['Pattern', category, match, 'IOC'])
            
            # Behavioral indicators
            if 'behavioral' in analysis_results:
                behavioral = analysis_results['behavioral'].get('indicators', {})
                for category, indicators in behavioral.items():
                    if isinstance(indicators, list):
                        for indicator in indicators:
                            writer.writerow(['Behavioral', category, indicator, 'IOC'])
            
            return output.getvalue()
        
        except Exception as e:
            return f"Error exporting CSV: {str(e)}"
    
    def generate_visualization_data(self, analysis_results):
        """
        Generate data for visualizations
        
        Args:
            analysis_results (dict): Analysis results
            
        Returns:
            dict: Visualization data
        """
        viz_data = {}
        
        # Threat level pie chart
        threat_assessment = analysis_results.get('threat_assessment', {})
        threat_level = threat_assessment.get('level', 'LOW')
        
        viz_data['threat_level_chart'] = {
            'labels': ['Threat Level'],
            'values': [threat_assessment.get('score', 0)],
            'colors': self._get_threat_colors(threat_level)
        }
        
        # Risk breakdown chart
        if 'threat_assessment' in analysis_results:
            breakdown = self._calculate_risk_breakdown(analysis_results)
            viz_data['risk_breakdown'] = {
                'categories': list(breakdown.keys()),
                'values': list(breakdown.values())
            }
        
        # Entropy timeline
        if 'entropy' in analysis_results:
            entropy_data = analysis_results['entropy']
            if 'section_entropies' in entropy_data:
                sections = entropy_data['section_entropies']
                viz_data['entropy_timeline'] = {
                    'offsets': [s['offset'] for s in sections],
                    'entropies': [s['entropy'] for s in sections]
                }
        
        # Pattern distribution
        if 'patterns' in analysis_results:
            patterns = analysis_results['patterns']
            pattern_counts = {}
            for category, matches in patterns.items():
                if isinstance(matches, list):
                    pattern_counts[category] = len(matches)
            
            viz_data['pattern_distribution'] = {
                'categories': list(pattern_counts.keys()),
                'counts': list(pattern_counts.values())
            }
        
        return viz_data
    
    def _get_threat_colors(self, threat_level):
        """Get colors for threat level visualization"""
        colors = {
            'LOW': '#28a745',
            'MEDIUM': '#ffc107',
            'HIGH': '#fd7e14',
            'CRITICAL': '#dc3545'
        }
        return colors.get(threat_level, '#6c757d')
    
    def create_summary_report(self, analysis_results):
        """
        Create a concise summary report
        
        Args:
            analysis_results (dict): Analysis results
            
        Returns:
            dict: Summary report
        """
        threat_assessment = analysis_results.get('threat_assessment', {})
        
        summary = {
            'file_name': analysis_results.get('filename', 'Unknown'),
            'threat_level': threat_assessment.get('level', 'Unknown'),
            'risk_score': threat_assessment.get('score', 0),
            'analysis_time': analysis_results.get('analysis_time', ''),
            'key_indicators': threat_assessment.get('reasons', [])[:3],  # Top 3 indicators
            'recommendation': threat_assessment.get('recommendation', ''),
            'iocs_found': self._count_total_indicators(analysis_results)
        }
        
        return summary
    
    def format_for_display(self, analysis_results):
        """
        Format results for display in Streamlit
        
        Args:
            analysis_results (dict): Analysis results
            
        Returns:
            dict: Formatted results for display
        """
        formatted = {
            'summary': self.create_summary_report(analysis_results),
            'threat_assessment': self._format_threat_assessment(analysis_results),
            'technical_details': self._format_technical_analysis(analysis_results),
            'iocs': self._extract_iocs(analysis_results),
            'recommendations': self._generate_recommendations(analysis_results),
            'visualizations': self.generate_visualization_data(analysis_results)
        }
        
        return formatted
