package burp.utilities.helpers;

public enum TaskType {
    Wrap("Wrap");

    private final String type;

    TaskType(String type) {
        this.type = type;
    }

    public static TaskType fromString(String type) {
        for (TaskType taskType : TaskType.values()) {
            if (taskType.type.equalsIgnoreCase(type)) {
                return taskType;
            }
        }
        return null;
    }

    public String getType() {
        return type;
    }
}
