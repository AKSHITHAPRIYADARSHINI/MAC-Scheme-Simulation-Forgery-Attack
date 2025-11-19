import random

def attacker_using_oracle(oracle):
    """
    Implementation of a forgery attack against the MAC scheme.
    This function queries the oracle to observe valid message-tag pairs,
    then creates a forged message by combining parts of different messages,
    and combining their corresponding tag parts.
    
    Args:
        oracle: A MACOracle instance
        
    Returns:
        (forged_msg, forged_tag, success): A tuple containing the forged message,
                                          the forged tag, and whether the forgery was successful
    """
    # Query the oracle to observe valid tags
    for _ in range(10):
        message = ''.join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", k=16))
        oracle.get_tag(message)

    # Split observed messages and tags into halves
    halves_db = []
    for m, t in oracle.get_observed():
        mid = len(m) // 2
        m0, m1 = m[:mid], m[mid:]
        t0, t1 = t[:mid], t[mid:]
        halves_db.append((m0, m1, t0, t1))

    # Choose random halves to combine
    (m0a, _, t0a, _) = random.choice(halves_db)
    (_, m1b, _, t1b) = random.choice(halves_db)

    # Create forged message and tag
    forged_msg = m0a + m1b
    forged_tag = t0a + t1b

    # Check if the forgery works
    success = oracle.verify(forged_msg, forged_tag)
    return forged_msg, forged_tag, success