import os
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import numpy as np
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from src.tp1.utils.config import logger


class Report:
    def __init__(self, capture, filename, summary):
        """
        Initialize a new report object
        Args:
            capture: Capture object containing network analysis data
            filename: Output filename for the report
            summary: Summary text from the capture analysis
        """
        self.capture = capture
        self.filename = filename
        self.title = "RAPPORT D'ANALYSE DE TRAFIC RÉSEAU"
        self.summary = summary
        self.array = ""
        self.graph = ""
        self.temp_graph_file = "temp_graph.png"  # Temporary file for the graph image

    def concat_report(self) -> str:
        """
        Concatenate all report components for text-based output
        Returns:
            str: Concatenated report content
        """
        content = f"\n\n{self.title}\n\n"
        content += f"\n{self.summary}\n\n"
        content += f"\n{self.array}\n\n"
        content += f"\n{self.graph}\n\n"

        return content

    def save(self, filename: str) -> None:
        """
        Save report as a PDF file
        Args:
            filename: Output filename
        """
        try:
            logger.info(f"Generating PDF report: {self.filename}")
            # Create the PDF document
            doc = SimpleDocTemplate(self.filename, pagesize=letter)
            styles = getSampleStyleSheet()
            
            # Create a list to hold the PDF elements
            elements = []
            
            # Add title
            title_style = ParagraphStyle(
                name='Title',
                parent=styles['Title'],
                fontSize=16,
                alignment=1,  # Center alignment
                spaceAfter=0.3*inch
            )
            elements.append(Paragraph(self.title, title_style))
            elements.append(Spacer(1, 0.3*inch))
            
            # Add capture information
            elements.append(Paragraph(f"Interface: {self.capture.interface}", styles["Normal"]))
            elements.append(Paragraph(f"Captured Packets: {len(self.capture.packets)}", styles["Normal"]))
            elements.append(Paragraph(f"Capture Duration: {self.capture.capture_time:.2f} seconds", styles["Normal"]))
            elements.append(Spacer(1, 0.2*inch))
            
            # Add protocol distribution graph if available
            if os.path.exists(self.temp_graph_file):
                elements.append(Paragraph("Protocol Distribution", styles["Heading2"]))
                elements.append(Image(self.temp_graph_file, width=6*inch, height=4*inch))
                elements.append(Spacer(1, 0.2*inch))
            
            # Add protocols table
            if self.capture.protocols:
                elements.append(Paragraph("Protocol Details", styles["Heading2"]))
                # Create table data from protocols
                table_data = [["Protocol", "Packets", "Percentage"]]
                sorted_protocols = self.capture.sort_network_protocols()
                for protocol, count in sorted_protocols.items():
                    percentage = (count / len(self.capture.packets)) * 100 if self.capture.packets else 0
                    table_data.append([protocol, str(count), f"{percentage:.1f}%"])
                
                # Create table with styling
                table = Table(table_data)
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ]))
                elements.append(table)
                elements.append(Spacer(1, 0.3*inch))
            
            # Add security analysis
            elements.append(Paragraph("Security Analysis", styles["Heading2"]))
            if self.capture.suspicious_activities:
                elements.append(Paragraph(f"Alert: {len(self.capture.suspicious_activities)} suspicious activities detected!", 
                                         ParagraphStyle(name='Alert', parent=styles['Normal'], textColor=colors.red)))
                
                for i, activity in enumerate(self.capture.suspicious_activities, 1):
                    elements.append(Paragraph(f"Suspicious Activity #{i}:", styles["Heading3"]))
                    elements.append(Paragraph(f"Type: {activity['type']}", styles["Normal"]))
                    elements.append(Paragraph(f"Details: {activity['details']}", styles["Normal"]))
                    elements.append(Paragraph(f"Source IP: {activity.get('attacker_ip', 'Unknown')}", styles["Normal"]))
                    if 'attacker_mac' in activity:
                        elements.append(Paragraph(f"Source MAC: {activity['attacker_mac']}", styles["Normal"]))
                    elements.append(Paragraph(f"Severity: {activity['severity']}", styles["Normal"]))
                    elements.append(Spacer(1, 0.1*inch))
            else:
                elements.append(Paragraph("No suspicious activities detected. Network traffic appears normal.", styles["Normal"]))
            
            # Build the PDF
            doc.build(elements)
            logger.info(f"PDF report successfully generated: {self.filename}")
            
            # Clean up temporary files
            if os.path.exists(self.temp_graph_file):
                os.remove(self.temp_graph_file)
                
        except Exception as e:
            logger.error(f"Error generating PDF report: {str(e)}")
            # Fallback to text report if PDF generation fails
            final_content = self.concat_report()
            with open(f"{self.filename}.txt", "w") as report:
                report.write(final_content)

    def generate(self, param: str) -> None:
        """
        Generate graph or array based on captured data
        Args:
            param: Type of element to generate ('graph' or 'array')
        Raises:
            ValueError: If an invalid parameter is provided
        """
        if param == "graph":
            self.graph = self._generate_graph()
        elif param == "array":
            self.array = self._generate_array()
        else:
            raise ValueError(f"Invalid parameter: {param}")
    
    def _generate_graph(self) -> str:
        """
        Generate a graph of protocol distribution
        Returns:
            str: Text description of the graph
        """
        try:
            # Get protocol data
            protocols = self.capture.get_all_protocols()
            if not protocols:
                logger.warning("No protocol data available for graph generation")
                return "No protocol data available for graph generation"
                
            # Sort protocols by count (most common first)
            sorted_protocols = self.capture.sort_network_protocols()
            
            # Extract labels and values
            labels = list(sorted_protocols.keys())
            values = list(sorted_protocols.values())
            
            # Create a pie chart
            plt.figure(figsize=(10, 8))
            explode = [0.05] * len(labels)  # Explode all slices slightly
            colors = plt.cm.tab20.colors[:len(labels)]
            
            plt.pie(values, labels=labels, autopct='%1.1f%%', startangle=140, 
                   shadow=True, explode=explode, colors=colors)
            plt.axis('equal')  # Equal aspect ratio ensures the pie chart is circular
            plt.title('Network Protocol Distribution')
            
            # Save the graph to a file
            plt.savefig(self.temp_graph_file, dpi=300, bbox_inches='tight')
            logger.info(f"Graph saved to {self.temp_graph_file}")
            
            # Return text description
            graph_text = "PROTOCOL DISTRIBUTION GRAPH\n\n"
            for protocol, count in sorted_protocols.items():
                percentage = (count / sum(values)) * 100
                graph_text += f"{protocol}: {count} packets ({percentage:.1f}%)\n"
                
            return graph_text
            
        except Exception as e:
            logger.error(f"Error generating graph: {str(e)}")
            return f"Error generating graph: {str(e)}"
    
    def _generate_array(self) -> str:
        """
        Generate a text-based table of protocol statistics
        Returns:
            str: Formatted table
        """
        try:
            protocols = self.capture.get_all_protocols()
            if not protocols:
                return "No protocol data available for table generation"
            
            # Create header
            array_text = "PROTOCOL STATISTICS TABLE\n\n"
            array_text += "{:<15} {:<10} {:<10}\n".format("Protocol", "Count", "Percentage")
            array_text += "-" * 40 + "\n"
            
            # Add rows
            sorted_protocols = self.capture.sort_network_protocols()
            total_packets = sum(protocols.values())
            
            for protocol, count in sorted_protocols.items():
                percentage = (count / total_packets) * 100 if total_packets else 0
                array_text += "{:<15} {:<10} {:<10.1f}%\n".format(protocol, count, percentage)
            
            return array_text
            
        except Exception as e:
            logger.error(f"Error generating table: {str(e)}")
            return f"Error generating table: {str(e)}"
