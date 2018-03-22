extern crate caps;
extern crate clap;
extern crate libc;
extern crate libmount;

use libc::*;
use std::ffi::CString;
use std::fs;
use std::io::Error;
use std::os::unix::fs::PermissionsExt;
use caps::{CapSet, Capability};
use std::path::Path;
use clap::{App, Arg};
use std::process::Command;

const NEW_DIRS: &'static [&'static str] = &["etc", "run", "usr", "var/log"];
const BIND_DIRS: &'static [&'static str] = &[
    "bin",
    "etc/alternatives",
    "etc/pki/tls/certs",
    "etc/pki/ca-trust",
    "etc/ssl/certs",
    "lib",
    "lib64",
    "sbin",
    "usr/bin",
    "usr/include",
    "usr/lib",
    "usr/lib64",
    "usr/libexec",
    "usr/sbin",
    "usr/share",
];

const TMP_DIRS: &'static [&'static str] = &["tmp", "run/lock", "var/tmp"];
const COPY_FILES: &'static [&'static str] =
    &["etc/group", "etc/passwd", "etc/resolv.conf", "etc/hosts"];

fn create_dirs(root: &str) {
    let mut dirs = NEW_DIRS.to_vec();
    dirs.extend(TMP_DIRS.iter());
    for d in dirs {
        fs::create_dir_all(format!("{}/{}", root, d))
            .expect(&format!("Failed to create dir {}", d));
    }
}

fn change_dir_permissions(root: &str) {
    for d in TMP_DIRS.iter() {
        let metadata = fs::metadata(format!("{}/{}", root, d))
            .expect(&format!("Failed to get metadata {}", d));
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o777);
    }
}

fn copy_files(root: &str) {
    for f in COPY_FILES {
        fs::copy(format!("/{}", f), format!("{}/{}", root, f))
            .expect(&format!("Failed to copy file {}", f));
    }
}

fn bind_mount(root: &str) {
    for d in BIND_DIRS {
        let sd = format!("/{}", d);
        let rd = format!("{}/{}", root, d);

        if !Path::new(&sd).exists() {
            continue;
        }
        let sdm = fs::metadata(&sd).expect(&format!("Failed to get metadata {}", &sd));
        if sdm.file_type().is_symlink() {
            let rdm = fs::metadata(&rd).expect(&format!("Failed to get metadata {}", &rd));
            if !rdm.file_type().is_symlink() {
                fs::create_dir_all(
                    Path::new(&rd)
                        .parent()
                        .expect(&format!("Failed to get parent dir path {}", &rd)),
                ).expect(&format!("Failed to create parent dir {}", &rd));
            }
            let sdl = fs::read_link(&sd).expect(&format!("Failed to read symlink {}", &sd));
            std::os::unix::fs::symlink(sdl, &rd)
                .expect(&format!("Failed to create symlink {}", &rd));
        } else {
            fs::create_dir_all(&rd).expect(&format!("Failed to create dir {}", &rd));
            if fs::read_dir(&rd).unwrap().count() == 0 {
                libmount::BindMount::new(Path::new(&sd), Path::new(&rd))
                    .recursive(false)
                    .readonly(true)
                    .mount()
                    .expect(&format!("Failed to mount {} to {}", &sd, &rd));
            }
        }
    }
}

fn makenod(path: &String, mode: mode_t, dev: dev_t) -> i32 {
    unsafe {
        mknod(
            CString::new(path.as_bytes())
                .expect("Error in construct CString")
                .as_bytes_with_nul()
                .as_ptr() as *const libc::c_char,
            mode,
            dev,
        )
    }
}

fn makedev(maj: u64, min: u64) -> dev_t {
    // pick up from <sys/sysmacros.h>
    ((min & 0xff) | ((maj & 0xfff) << 8) | (((min & !0xff)) << 12) | (((maj & !0xfff)) << 32))
        as dev_t
}

fn make_device_if_not_exists(path: String, mode: mode_t, dev: dev_t) {
    if !Path::new(&path).exists() {
        let err = makenod(&path, S_IFCHR | mode, dev);
        handle_os_error(err, format!("{}", path));
    }
}

fn make_devices(root: &str) {
    fs::create_dir_all(format!("{}/dev", root)).expect("Cannot create /dev dir");
    make_device_if_not_exists(format!("{}/dev/null", root), 0o666, makedev(1, 3));
    make_device_if_not_exists(format!("{}/dev/zero", root), 0o666, makedev(1, 5));
    for r in &["random", "urandom"] {
        make_device_if_not_exists(format!("{}/dev/{}", root, r), 0o444, makedev(1, 9));
    }
}

fn drop_capabilities() {
    let allowed_caps = vec![
        Capability::CAP_SETGID,
        Capability::CAP_SETGID,
        Capability::CAP_NET_BIND_SERVICE,
    ];
    let cur = caps::read(None, CapSet::Bounding).expect("Cannot read capabilityes");
    for c in cur {
        if allowed_caps.contains(&c) {
            continue;
        }
        caps::drop(None, CapSet::Bounding, c).expect(&format!("Cannot drop capability {}", c));
    }
}

fn exec_command<'a>(commands: Option<clap::Values>) {
    let cmds = match commands {
        Some(vs) => vs.map(|v| v).collect::<Vec<&str>>(),
        None => vec!["bash", "-i"],
    };
    let _ = Command::new(cmds[0])
        .args(&cmds[1..])
        .status()
        .unwrap_or_else(|e| panic!("Cannot exec: {}", e));
}

fn exec_chroot(root: &str) {
    std::env::set_current_dir(&root).expect(&format!("Cannot change current dir to {}", &root));
    let err = unsafe {
        chroot(CString::new(".".as_bytes())
            .expect("Error in construct CString")
            .as_bytes_with_nul()
            .as_ptr() as *const libc::c_char)
    };
    handle_os_error(err, "chroot");
}

fn handle_os_error<T: std::fmt::Display>(err: i32, action: T) {
    if err != 0 {
        panic!(
            "Error: {{action: {}, code: {}, msg: {} }}",
            action,
            err,
            Error::last_os_error()
        );
    }
}

fn get_args<'a>() -> clap::ArgMatches<'a> {
    App::new("jl")
        .version("0.0.1")
        .about("Simple jailing tool using chroot")
        .args(&[
            Arg::with_name("root")
                .short("r")
                .long("root")
                .value_name("PATH")
                .help("root directory to chroot")
                .takes_value(true)
                .required(true),
            Arg::with_name("command")
                .help("command")
                .multiple(true)
                .required(false),
        ])
        .get_matches()
}

fn main() {
    let args = get_args();
    let root = args.value_of("root").unwrap();
    let commands = args.values_of("command");
    if !Path::new(&root).exists() {
        panic!("Cannot find root path {}", &root);
    }
    create_dirs(root);
    change_dir_permissions(root);
    copy_files(root);
    bind_mount(root);
    make_devices(root);
    exec_chroot(root);
    drop_capabilities();
    exec_command(commands);
}
