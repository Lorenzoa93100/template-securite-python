def hello_world() -> str:
    """
    Hello world function
    """
    return "hello world"


def get_mac(ip_address):
    """
    Get the MAC address of a device on the network using ARP
    Args:
        ip_address (str): The IP address to look up
    Returns:
        str: The MAC address if found, None otherwise
    """
    from scapy.layers.l2 import ARP, Ether
    from scapy.sendrecv import srp
    import re
    
    try:
        # Create ARP request packet
        arp_request = ARP(pdst=ip_address)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        
        # Send packet and get response
        answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        
        # Return MAC if found
        if answered_list:
            return answered_list[0][1].hwsrc
    except Exception:
        pass
    
    return None


def choose_interface() -> str:
    """
    List available network interfaces and return user's choice
    Returns:
        str: The name of the selected interface
    """
    from scapy.arch import get_if_list, get_if_addr
    from src.tp1.utils.config import logger
    
    # Get list of available interfaces
    interfaces = get_if_list()
    
    if not interfaces:
        logger.error("No network interfaces found")
        return ""
    
    logger.info("Available network interfaces:")
    # Display interfaces with their addresses
    for idx, iface in enumerate(interfaces):
        try:
            ip_addr = get_if_addr(iface)
            logger.info(f"[{idx}] {iface} ({ip_addr})")
        except Exception as e:
            logger.info(f"[{idx}] {iface} (No IP address available)")
    
    # Ask user to select an interface
    while True:
        try:
            choice = input("Select an interface by number: ")
            idx = int(choice)
            if 0 <= idx < len(interfaces):
                selected_interface = interfaces[idx]
                logger.info(f"Selected interface: {selected_interface}")
                return selected_interface
            else:
                logger.warning(f"Invalid selection. Please choose between 0 and {len(interfaces)-1}")
        except ValueError:
            logger.warning("Please enter a valid number")
        except KeyboardInterrupt:
            logger.warning("Interface selection canceled")
            return ""
