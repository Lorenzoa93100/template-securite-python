from src.tp1.utils.lib import hello_world, get_mac
from unittest.mock import patch, MagicMock


def test_when_hello_world_then_return_hello_world():
    # Given
    string = "hello world"

    # When
    result = hello_world()

    # Then
    assert result == string


@patch('src.tp1.utils.lib.get_if_list')
@patch('builtins.input')
def test_when_choose_interface_then_return_selected_interface(mock_input, mock_get_if_list):
    # Import locally to avoid circular imports during test
    from src.tp1.utils.lib import choose_interface
    
    # Given
    mock_get_if_list.return_value = ['eth0', 'wlan0']
    mock_input.return_value = "0"  # Simulate user selecting the first interface
    
    # When
    with patch('src.tp1.utils.lib.get_if_addr', return_value='192.168.1.1'):
        result = choose_interface()
    
    # Then
    assert result == "eth0"  # Should return the selected interface
    

@patch('src.tp1.utils.lib.srp')
def test_when_get_mac_then_return_mac_address(mock_srp):
    # Given
    mock_response = MagicMock()
    mock_response.hwsrc = "00:11:22:33:44:55"
    
    mock_pair = MagicMock()
    mock_pair.__getitem__.return_value = MagicMock()
    mock_pair.__getitem__.return_value.__getitem__.return_value = mock_response
    
    mock_srp.return_value = ([mock_pair], MagicMock())
    
    # When
    result = get_mac("192.168.1.1")
    
    # Then
    assert result == "00:11:22:33:44:55"


@patch('src.tp1.utils.lib.srp')
def test_when_get_mac_fails_then_return_none(mock_srp):
    # Given
    mock_srp.return_value = ([], MagicMock())
    
    # When
    result = get_mac("192.168.1.1")
    
    # Then
    assert result is None
