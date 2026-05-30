char* get_system_project_name() {
    return "projname";
}

char* get_system_generic_model_name() {
    int model_id = 0;

    if (model_id == 0) {
        return "modelname0";
    }
    if (model_id == 1) {
        return "modelname1";
    }
}

int get_system_version() {
    return 1000;
}