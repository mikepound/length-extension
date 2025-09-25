package uk.ac.nottingham.cryptography.banking;

import java.util.Arrays;

public class BankTransaction {
    private String fromAccount;
    private String toAccount;
    private String amount;

    public BankTransaction(String transaction) {
        this.fromAccount = "";
        this.toAccount = "";
        this.amount = "";

        Arrays.stream(transaction.split(";"))
                .forEach(item -> {
                    String[] itemArr = item.split(":");
                    switch (itemArr[0]) {
                        case "from":
                            this.fromAccount = itemArr[1];
                            break;
                        case "to":
                            this.toAccount = itemArr[1];
                            break;
                        case "amount":
                            this.amount = itemArr[1];
                    }
                });
    }

    public String getAmount() {
        return amount;
    }

    public String getToAccount() {
        return toAccount;
    }

    public String getFromAccount() {
        return fromAccount;
    }
}
