import json
import csv
import sys


def create_entry(name, value, unit):
    entry = {
        "name": name,
        "value": value,
        "unit": unit
    }
    return entry


def rewrite_csv(src_file):
    try:
        result = []
        with open(src_file, 'r', newline='') as file:
            reader = csv.reader(file)
            next(reader)
            for row in reader:
                if row[1] == "" or row[1] is None:
                    continue
                else:
                    name = f"{row[0]} {row[1]}"
                if name.startswith("Min") or name.startswith("Max") or name.startswith("Median") or not name.startswith("50th"):
                    continue
                unit = row[3]
                value = float(row[2])
                if unit == "ops/s":
                    value = 1 / value
                    unit = "s/ops"
                elif unit == "docs/s":
                    value = 1 / value
                    unit = "s/docs"
                entry = create_entry(name, value, unit)
                result.append(entry)
            return result
    except Exception as e:
        print(f"Failed to rewrite benchmark results: {e} {row}")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Wrong number of arguments")
        sys.exit(1)
    else:
        src = sys.argv[1]
        dest = sys.argv[2]
        json_res = rewrite_csv(src)
        with open(dest, 'w') as f:
            json.dump(json_res, f, indent=4)
