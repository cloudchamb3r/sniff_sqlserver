
if __name__ == "__main__":
    import argparse
    from . import ascii_logo

    parser = argparse.ArgumentParser(
        description=ascii_logo, 
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '<ip>' , 
        type = str, 
        required = True,
        help= 'SqlServer IPAddress to Sniff'
    )

    parser.add_argument(
        '-p', '--port',
        type = int,
        dest = '', 
        default = 1433, 
        help = 'SqlServer Port to Sniff (default: 1433)'
    )

    args = parser.parse_args()

    print(args.accumulate(args.integers))