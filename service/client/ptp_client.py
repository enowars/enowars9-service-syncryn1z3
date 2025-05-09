import sys
sys.path.append("build")

import ptp_connection

def main():
    # Create UDP socket
    with ptp_connection.PtpConnection(42) as connection:
        pass

if __name__ == "__main__":
    main()
