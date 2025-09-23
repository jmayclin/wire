#!/usr/bin/env python3

import random
import sys

def simulate_session_resumption(fleet_size, split_brain_portion, num_handshakes):
    """
    Simulate session resumption in a split brain fleet.
    
    Args:
        fleet_size: Total number of hosts in the fleet
        split_brain_portion: Portion of the fleet that issues format A tickets (0.0 to 1.0)
                            The remaining (1 - split_brain_portion) issues format B tickets
        num_handshakes: Number of handshakes to simulate
        
    Returns:
        Tuple of (full_handshakes, total_handshakes)
    """
    # Calculate how many hosts issue format A vs format B
    format_a_hosts = int(fleet_size * split_brain_portion)
    format_b_hosts = fleet_size - format_a_hosts
    
    # Initialize counters
    full_handshakes = 0
    total_handshakes = 0
    
    # Initially, client has no session ticket
    client_ticket_format = None
    
    # Simulate handshakes
    for _ in range(num_handshakes):
        # Randomly select a host
        # If random number is less than split_brain_portion, it's a format A host
        # Otherwise, it's a format B host
        host_format = 'A' if random.random() < split_brain_portion else 'B'
        
        # Determine if a full handshake is needed
        if client_ticket_format is None or client_ticket_format != host_format:
            # Client has no ticket or has a ticket in a format the host doesn't understand
            full_handshakes += 1
        
        # After connecting, client gets a ticket in the host's format
        client_ticket_format = host_format
        
        # Increment total handshakes
        total_handshakes += 1
    
    return full_handshakes, total_handshakes

def main():
    # Constants
    FLEET_SIZE = 3
    SPLIT_BRAIN_PORTION = 0.666  # 50% of hosts issue format A, 50% issue format B
    NUM_HANDSHAKES = 10_000_000
    
    # Validate inputs
    if not (0 <= SPLIT_BRAIN_PORTION <= 1):
        print("Error: split_brain_portion must be between 0.0 and 1.0")
        sys.exit(1)
    
    if FLEET_SIZE <= 0 or NUM_HANDSHAKES <= 0:
        print("Error: fleet_size and num_handshakes must be positive integers")
        sys.exit(1)
    
    # Run simulation
    full_handshakes, total_handshakes = simulate_session_resumption(
        FLEET_SIZE, SPLIT_BRAIN_PORTION, NUM_HANDSHAKES
    )
    
    # Calculate probability of session resumption
    if total_handshakes > 0:
        resumption_probability = 1 - (full_handshakes / total_handshakes)
    else:
        resumption_probability = 0
    
    # Print results
    print(f"Fleet Size: {FLEET_SIZE}")
    print(f"Split Brain Portion (Format A): {SPLIT_BRAIN_PORTION:.2f}")
    print(f"Number of Handshakes: {NUM_HANDSHAKES}")
    print(f"Full Handshakes: {full_handshakes} out of {total_handshakes} ({full_handshakes/total_handshakes:.2%})")
    print(f"Session Resumption Probability: {resumption_probability:.2%}")

if __name__ == "__main__":
    main()
