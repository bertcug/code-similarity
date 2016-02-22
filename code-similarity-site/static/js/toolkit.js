/**
 * 
 */

function undisable(id){
	$(id).attr("disabled", false);
	$("#btn").attr("disabled", false);
}

function onSubmit(){
	$("[disabled='true']").attr("disabled", false);
	//$("#btn").attr("disabled", true);
	return true;
}
