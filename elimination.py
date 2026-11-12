def eliminate(dir_list, file_name, pred_positive_signals, equivalence=True):

    node_connect = []
    node_features = []
    graph_labels = []
    graph_indicator = []
    node_labels = []
    graph_num_list = []
    feature_dict = {}
    num_begin_list = []
    path_list = []

    Gate_tree = create_Gate_tree(os.path.join(file_dir, file_name))

    _node_connect, _node_features, _node_labels, num_dict, _feature_dict = tree_to_matrix(Gate_tree, feature_dict,
                                                                                          len(node_features))
    node_dict = Gate_tree.node_dict


    for key in node_dict:
        node = node_dict[key]
        if (node.type != 'input' and node.type != 'output' and node.type != 'wire' and node.type != 'constant'):
            flag1 = 0

            counter = 0
            for node_child in node.child_list:

                flag2 = 0
                flag3 = 0

                for node_child_parent in node_child.parent_list:
                    for node_child_parent_parent in node_child_parent.parent_list:
                        counter += 1
                        if node_child_parent_parent.name not in pred_positive_signals:
                            flag2 += 1
                for first_child in node_child.child_list:
                    for node_child_child in first_child.child_list:
                        if node_child_child.name in pred_positive_signals:
                            flag3 += 1

                if (flag3 == 0) and (flag2 > 0) and (
                        node_child.name in pred_positive_signals):
                    pred_positive_signals.remove(node_child.name)

        if node.type == "output":
            flag6 = 0
            for node_child in node.child_list:
                for node_child_child in node_child.child_list:
                    if node_child_child.name in pred_positive_signals:
                        flag6 += 1
            if (flag6 == 0) and (node.name in pred_positive_signals):
                pred_positive_signals.remove(node.name)



    file_feature_path = f'{file_dir}/feature_matrix_signal.csv'
    df = pd.read_csv(file_feature_path, header=None)
    df_key = df.iloc[:, 0].astype(str).str.strip()
    name_scoap_dict = {}
    for name in pred_positive_signals:
        matched_rows = df[df_key == name]
        if matched_rows.empty:
            print(f"No data found for name: {name}")
            continue
        cc0_vals = matched_rows.iloc[:, 77]
        cc1_vals = matched_rows.iloc[:, 78]
        co_vals = matched_rows.iloc[:, 79]

        scoap_sum = (cc0_vals + cc1_vals + co_vals).sum()

        name_scoap_dict[name] = scoap_sum


    top_5_names = sorted(name_scoap_dict.items(), key=lambda x: x[1], reverse=True)[:5]
    top_5_names = [name for name, scoap in top_5_names]
    pred_positive_signals = top_5_names


    for key in node_dict:
        node = node_dict[key]
        if (node.type != 'input' and node.type != 'output' and node.type != 'wire' and node.type != 'constant'):
            flag1 = 0
            flag3 = 0
            counter = 0
            for node_child in node.child_list:
                flag2 = 0
                if node_child.name not in pred_positive_signals:
                    flag1 += 1
                for node_child_parent in node_child.parent_list:
                    for node_child_parent_parent in node_child_parent.parent_list:
                        counter += 1
                        if node_child_parent_parent.name not in pred_positive_signals:
                            flag2 += 1
                if flag2 == 0:
                    pred_positive_signals.append(node_child.name)

            if flag1 == 0:
                for node_parent in node.parent_list:
                    pred_positive_signals.append(node_parent.name)
    Trojan_signals = list(set(pred_positive_signals))

    payload_name = "None"
    payload_node = ""
    temporary = ""
    for key in node_dict:
        node = node_dict[key]

        if (node.type == 'input' or node.type == 'output' or node.type == 'wire' or node.type == 'constant'):
            flag4 = 0
            flag5 = 0
            for node_child in node.child_list:
                for node_child_child in node_child.child_list:
                    if node_child_child.name in pred_positive_signals:
                        flag4 += 1
            for node_parent in node.parent_list:
                for node_parent_parent in node_parent.parent_list:
                    if node_parent_parent.name in pred_positive_signals:
                        flag5 += 1
            if (flag4 > 0) and (flag5 == 0) and node.name not in pred_positive_signals:
                payload_name = node.name
                payload_node = node

    if payload_node != "":
        for payload_node_child in payload_node.child_list:
            for payload_child in payload_node_child.child_list:
                if payload_child.name not in pred_positive_signals:
                    temporary = payload_child.name

    if (os.path.exists(os.path.join(dir_list, file_name)) == True) and (temporary != ""):
        file_path = os.path.join(file_dir, file_name)

        with open(file_path, 'r') as file:
            lines = file.readlines()
            pattern_temp = re.compile(r'\b' + re.escape(temporary) + r'\b\s*,?\s*')
            filtered_lines = []

            for line in lines:
                modified_line = line

                modified_line = pattern_temp.sub(payload_name, modified_line)
                if not any(trojan_str in modified_line for trojan_str in Trojan_signals):
                    filtered_lines.append(modified_line)
        output_file_path = os.path.join(file_dir, "normal.v")
        with open(output_file_path, 'w', encoding='utf-8') as file:
            file.writelines(filtered_lines)
