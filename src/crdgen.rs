use nephelite_lib::Credential;
use kube::CustomResourceExt;

fn main() {
    print!("{}", serde_yaml::to_string(&Credential::crd()).unwrap())
}