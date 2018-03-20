
            #compute the Hash value of each method
            methodmd5 = hashlib.md5()
            methodmd5.update(method_opcode_str)
            method_md5_index =methodmd5.hexdigest()

            method_name_list.append(filename)
            set_invoke_info = set(invoke_info)
            method_info.append(set_invoke_info)
            method_info.append(method_md5_index)
            
            method_dict[filename] = method_info
            
    return method_dict, classes_list       
   
#compute the HASH Value of the classes in classes_list
#using the classes_list, method_dict, and method_name_list
def class_info_index(classes_list, method_dict):
    classes_info_dict = {}
    classcount = 0
    method_list = method_dict.keys()
    #print "method_list", method_list
    for cls_nc_pair in classes_list:
        class_info = []
        class_cfg = ""
        method_hash_list = []
        classname = cls_nc_pair[0]
        class_invoke_set = set()
        for method in method_list:
            method_info = method_dict[method]
            #print method.count(classname)
            if method.count(classname[1:]) == 1:
                method_hash = method_info[1]
#                print method_hash
                method_hash_list.append(method_hash)
                
                method_invoke_set = method_info[0]
                class_invoke_set.update(method_invoke_set)
                
        method_hash_list.sort()
