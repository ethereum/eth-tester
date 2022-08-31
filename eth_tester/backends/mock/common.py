def calculate_effective_gas_price(transaction, block):
    return (
        min(
            transaction["max_fee_per_gas"],
            transaction["max_priority_fee_per_gas"] + block["base_fee_per_gas"],
        )
        if "max_fee_per_gas" in transaction
        else transaction["gas_price"]
    )
