from unittest.mock import patch, MagicMock
import pytest
from src.tp1.utils.capture import Capture
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP


@pytest.fixture
def capture_instance():
    with patch('src.tp1.utils.capture.choose_interface', return_value='eth0'):
        capture = Capture()
    return capture


@patch('src.tp1.utils.capture.sniff')
def test_capture_trafic_success(mock_sniff, capture_instance):
    # Given
    mock_packets = [MagicMock(), MagicMock()]
    mock_sniff.return_value = mock_packets
    
    # When
    capture_instance.capture_trafic(duration=5)
    
    # Then
    assert capture_instance.packets == mock_packets
    mock_sniff.assert_called_once_with(iface='eth0', timeout=5)


def test_sort_network_protocols(capture_instance):
    # Given
    capture_instance.protocols = {'TCP': 5, 'UDP': 3, 'ICMP': 7}
    
    # When
    result = capture_instance.sort_network_protocols()
    
    # Then
    assert result == {'ICMP': 7, 'TCP': 5, 'UDP': 3}


def test_get_all_protocols(capture_instance):
    # Given
    capture_instance.protocols = {'TCP': 5, 'UDP': 3, 'ICMP': 7}
    
    # When
    result = capture_instance.get_all_protocols()
    
    # Then
    assert result == {'TCP': 5, 'UDP': 3, 'ICMP': 7}


@patch('src.tp1.utils.capture.logger')
def test_analyse_no_packets(mock_logger, capture_instance):
    # Given
    capture_instance.packets = []
    
    # When
    capture_instance.analyse()
    
    # Then
    mock_logger.warning.assert_called_once_with("No packets captured. Cannot perform analysis.")


@patch.object(Capture, '_detect_arp_spoofing')
@patch.object(Capture, '_detect_port_scanning')
@patch.object(Capture, '_detect_sql_injection')
@patch.object(Capture, '_detect_excessive_icmp')
def test_analyse_calls_detection_methods(mock_icmp, mock_sql, mock_port, mock_arp, capture_instance):
    # Given
    capture_instance.packets = [MagicMock()]
    
    # When
    capture_instance.analyse()
    
    # Then
    mock_arp.assert_called_once()
    mock_port.assert_called_once()
    mock_sql.assert_called_once()
    mock_icmp.assert_called_once()


def test_detect_arp_spoofing(capture_instance):
    # Given - Create ARP packets with same IP but different MACs
    arp_packet1 = Ether()/ARP(op=2, psrc="192.168.1.1", hwsrc="00:11:22:33:44:55")
    arp_packet2 = Ether()/ARP(op=2, psrc="192.168.1.1", hwsrc="AA:BB:CC:DD:EE:FF")
    capture_instance.packets = [arp_packet1, arp_packet2]
    
    # When
    capture_instance._detect_arp_spoofing()
    
    # Then
    assert len(capture_instance.suspicious_activities) == 1
    assert capture_instance.suspicious_activities[0]['type'] == 'ARP Spoofing'


def test_get_summary(capture_instance):
    # Given
    expected_summary = "Test Summary"
    capture_instance.summary = expected_summary
    
    # When
    result = capture_instance.get_summary()
    
    # Then
    assert result == expected_summary
