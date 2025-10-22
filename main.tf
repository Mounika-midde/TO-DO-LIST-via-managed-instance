
# ----------------------------------
# VPC
# ----------------------------------
resource "aws_vpc" "my-vpc-todo" {
  cidr_block = "10.0.0.0/16"
  enable_dns_support   = true
enable_dns_hostnames = true

  tags = {
    Name = "my-vpc-todo"
  }
}

# ----------------------------------
# Subnets - Public
# ----------------------------------
resource "aws_subnet" "todo-public" {
  count                   = 2
  vpc_id                  = aws_vpc.my-vpc-todo.id
  cidr_block              = ["10.0.1.0/24", "10.0.2.0/24"][count.index]
  availability_zone       = ["us-east-1a", "us-east-1b"][count.index]
  map_public_ip_on_launch = true
  tags = {
    Name = ["todo-public-1", "todo-public-2"][count.index]
  }
}

# ----------------------------------
# Subnets - Private
# ----------------------------------
resource "aws_subnet" "todo-private" {
  count             = 3
  vpc_id            = aws_vpc.my-vpc-todo.id
  cidr_block        = ["10.0.3.0/24", "10.0.4.0/24", "10.0.5.0/24"][count.index]
  availability_zone = ["us-east-1a", "us-east-1a", "us-east-1b"][count.index]
  tags = {
    Name = ["todo-private-ecs", "todo-private-rds1", "todo-private-rds2"][count.index]
  }
}

# ----------------------------------
# Internet Gateway
# ----------------------------------
resource "aws_internet_gateway" "todo-igw" {
  vpc_id = aws_vpc.my-vpc-todo.id
  tags = {
     Name = "todo-igw"
  }
}

# ----------------------------------
# NAT Gateway
# ----------------------------------
resource "aws_eip" "todo-nat-eip" {
  tags = {
    Name = "todonateip"
  }
}

resource "aws_nat_gateway" "todo-nat" {
  allocation_id = aws_eip.todo-nat-eip.id
  subnet_id     = aws_subnet.todo-public[0].id
  tags = {
    Name = "todo-NAT"
  }
  depends_on = [aws_internet_gateway.todo-igw]
}

# ----------------------------------
# Route Tables
# ----------------------------------
# Public
resource "aws_route_table" "todo-public-rt" {
  vpc_id = aws_vpc.my-vpc-todo.id
  tags = { Name = "todo-public-rt" }
}

resource "aws_route" "todo-public-route" {
  route_table_id         = aws_route_table.todo-public-rt.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.todo-igw.id
}

resource "aws_route_table_association" "todo-public-rt-assoc" {
  count          = 2
  subnet_id      = aws_subnet.todo-public[count.index].id
  route_table_id = aws_route_table.todo-public-rt.id
}

# Private
resource "aws_route_table" "todo-private-rt" {
  vpc_id = aws_vpc.my-vpc-todo.id
  tags = { Name = "todo-private-rt" }
}

resource "aws_route" "todo-private-route" {
  route_table_id         = aws_route_table.todo-private-rt.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.todo-nat.id
}

resource "aws_route_table_association" "todo-private-rt-assoc" {
  count          = 3
  subnet_id      = aws_subnet.todo-private[count.index].id
  route_table_id = aws_route_table.todo-private-rt.id
}

# ----------------------------------
# Security Groups
# ----------------------------------
# ALB
resource "aws_security_group" "alb-sg" {
  name   = "alb-sg"
  vpc_id = aws_vpc.my-vpc-todo.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ECS
resource "aws_security_group" "ecs-sg" {
  name   = "ecs-sg"
  vpc_id = aws_vpc.my-vpc-todo.id

  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb-sg.id]
  }

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb-sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# RDS
resource "aws_security_group" "rds-sg" {
  name   = "rds-sg"
  vpc_id = aws_vpc.my-vpc-todo.id

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs-sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ----------------------------------
# RDS Database
# ----------------------------------
resource "aws_db_subnet_group" "todo-db-subnet-group" {
  name       = "todo-db-subnet-group"
  subnet_ids = [aws_subnet.todo-private[1].id, aws_subnet.todo-private[2].id]
}

resource "aws_db_instance" "todo-db" {
  identifier             = "todo-rds"
  engine                 = "mysql"
  engine_version         = "8.0"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "admin"
  password               = "mounika11"
  db_subnet_group_name   = aws_db_subnet_group.todo-db-subnet-group.name
  vpc_security_group_ids = [aws_security_group.rds-sg.id]
  skip_final_snapshot    = true
  publicly_accessible    = false
  multi_az               = false
  storage_encrypted      = true
}

# ----------------------------------
# Secrets Manager for DB Password
# ----------------------------------
resource "aws_secretsmanager_secret" "db_password" {
  name = "todo-db-password-new"
}

resource "aws_secretsmanager_secret_version" "db_password_version" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = aws_db_instance.todo-db.password
  depends_on    = [aws_db_instance.todo-db]
}

# ----------------------------------
# ALB
# ----------------------------------
resource "aws_lb" "todo-lb" {
  name               = "todo-alb"
  load_balancer_type = "application"
  subnets            = [aws_subnet.todo-public[0].id, aws_subnet.todo-public[1].id]
  security_groups    = [aws_security_group.alb-sg.id]
  internal           = false
}

resource "aws_lb_target_group" "frontend-tg" {
  name        = "frontend-tg"
  vpc_id      = aws_vpc.my-vpc-todo.id
  port        = 80
  protocol    = "HTTP"
  target_type = "ip"
}

resource "aws_lb_target_group" "backend-tg" {
  name        = "backend-tg"
  vpc_id      = aws_vpc.my-vpc-todo.id
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  health_check {
    path                = "/api/health"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
}

resource "aws_lb_listener" "frontend" {
  load_balancer_arn = aws_lb.todo-lb.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.frontend-tg.arn
  }
}

resource "aws_lb_listener_rule" "backend" {
  listener_arn = aws_lb_listener.frontend.arn
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.backend-tg.arn
  }
  condition {
    path_pattern {
      values = ["/api/*"]
    }
  }
}

# ----------------------------------
# ECR Repositories
# ----------------------------------
resource "aws_ecr_repository" "ecr-frontend" {
  name = "ecr-repo-frontend"
force_delete = true

}

resource "aws_ecr_repository" "ecr-backend" {
  name = "ecr-repo-backend"
force_delete = true
}

# ----------------------------------
# ECS Cluster
# ----------------------------------
resource "aws_ecs_cluster" "todo-cluster" {
  name = "todo-cluster"
}

# ----------------------------------
# IAM Roles & Instance Profile for EC2 (managed instances)
# ----------------------------------
# EC2 role for ECS managed instances
resource "aws_iam_role" "ec2_ecs_role" {
  name               = "ec2ECSRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "ec2.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
}

# Attach AmazonEC2ContainerServiceforEC2Role (classic) so instances can register with ECS
resource "aws_iam_role_policy_attachment" "ec2_ecs_policy_attach" {
  role       = aws_iam_role.ec2_ecs_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
}

# Attach SSM permissions for execute-command / session manager
resource "aws_iam_role_policy" "ec2_ssm_policy" {
  name = "EC2SSMPolicy"
  role = aws_iam_role.ec2_ecs_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "ssm:DescribeAssociation",
          "ssm:GetDeployablePatchSnapshotForInstance",
          "ssm:GetDocument",
          "ssm:DescribeDocument",
          "ssm:GetManifest",
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:ListAssociations",
          "ssm:ListInstanceAssociations",
          "ssm:UpdateInstanceAssociationStatus",
          "ssm:UpdateInstanceInformation",
          "ssmmessages:*",
          "ec2messages:*",
          "cloudwatch:PutMetricData",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
          "logs:PutLogEvents"
        ],
        Resource = "*"
      }
    ]
  })
}

# Instance profile used by EC2 instances launched by capacity provider
resource "aws_iam_instance_profile" "todo_ec2_instance_profile" {
  name = "todo-ec2-instance-profile"
  role = aws_iam_role.ec2_ecs_role.name
}

# ----------------------------------
# ECS Infra Role (lets ECS create/terminate EC2 instances)
# ----------------------------------
resource "aws_iam_role" "ecs_infra_role" {
  name               = "ECSInfraRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "ecs.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
}

# Custom policy to allow ECS to manage EC2 instances and pass the EC2 role
resource "aws_iam_role_policy" "ecs_infra_custom_policy" {
  name = "ecs-infra-custom-policy"
  role = aws_iam_role.ecs_infra_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "ec2:Describe*",
          "ec2:RunInstances",
          "ec2:TerminateInstances",
          "ec2:CreateTags",
          "ec2:DeleteTags",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSubnets",
          "ec2:DescribeVpcs",
          "ec2:DescribeKeyPairs",
          "ec2:DescribeInstanceTypes",
          "ec2:DescribeImages",
          "ec2:DescribeVolumes",
          "ec2:AttachVolume",
          "ec2:CreateLaunchTemplate",
          "ec2:CreateLaunchTemplateVersion",
          "ec2:DeleteLaunchTemplate",
          "ec2:DeleteLaunchTemplateVersions",
          "ec2:DescribeLaunchTemplates",
          "ec2:DescribeLaunchTemplateVersions",
          "ec2:CreateFleet",
          "ec2:DescribeFleetInstances",
          "ec2:DescribeFleets"
        ],
        Resource = "*"
      },
      {
        Effect = "Allow",
        Action = [
          "iam:PassRole"
        ],
        Resource = [aws_iam_role.ec2_ecs_role.arn]
      }
    ]
  })
}

# ----------------------------------
# ECS Capacity Provider (Managed Instances)
# ----------------------------------
resource "aws_ecs_capacity_provider" "todo_capacity_provider" {
  name    = "todo-capacity-provider"
  cluster = aws_ecs_cluster.todo-cluster.name

  managed_instances_provider {
    infrastructure_role_arn = aws_iam_role.ecs_infra_role.arn
    propagate_tags          = "CAPACITY_PROVIDER"

    instance_launch_template {
      ec2_instance_profile_arn = aws_iam_instance_profile.todo_ec2_instance_profile.arn
      monitoring               = "BASIC"

      network_configuration {
        # Use the private subnets for instance ENIs
        subnets         = [aws_subnet.todo-private[0].id, aws_subnet.todo-private[1].id, aws_subnet.todo-private[2].id]
        security_groups = [aws_security_group.ecs-sg.id]
      }

      storage_configuration {
        storage_size_gib = 30
      }

      instance_requirements {
        memory_mib {
          min = 1024
          max = 8192
        }

        vcpu_count {
          min = 1
          max = 4
        }

        instance_generations = ["current"]
        cpu_manufacturers    = ["intel", "amd"]
      }
    }
  }
}


# ----------------------------------
# IAM Roles for Tasks (Execution & Task Role)
# ----------------------------------
# ECS Task Execution Role
resource "aws_iam_role" "ecs_task_execution_role" {
  name = "ecs-task-execution-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "ecs-tasks.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_exec_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# ECS Task Role (for tasks to call AWS APIs)
resource "aws_iam_role" "ecs_task_role" {
  name = "ecs-task-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "ecs-tasks.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "ecs_task_policy" {
  name = "ecs-task-policy"
  role = aws_iam_role.ecs_task_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "ssm:SendCommand",
          "ssm:StartSession",
          "ssm:DescribeSessions",
          "ssm:GetConnectionStatus",
          "rds:DescribeDBInstances",
          "s3:GetObject",
          "s3:PutObject"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_ssm_managed" {
  role       = aws_iam_role.ecs_task_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# ----------------------------------
# CloudWatch Log Groups for ECS Tasks
# ----------------------------------
resource "aws_cloudwatch_log_group" "frontend_logs" {
  name              = "/ecs/frontend"
  retention_in_days = 7
}

resource "aws_cloudwatch_log_group" "backend_logs" {
  name              = "/ecs/backend"
  retention_in_days = 7
}

# ----------------------------------
# ECS Task Definitions (frontend & backend) - awsvpc + managed instances
# ----------------------------------
resource "aws_ecs_task_definition" "frontend_task" {
  family                   = "frontend-task"
  requires_compatibilities = ["MANAGED_INSTANCES"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([
    {
      name      = "frontend"
      image     = "${aws_ecr_repository.ecr-frontend.repository_url}:latest"
      essential = true
      portMappings = [
        {
          containerPort = 80
          protocol      = "tcp"
        }
      ]
      memory = 512
      cpu    = 256
      linuxParameters = {
        initProcessEnabled = true
      }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.frontend_logs.name
          awslogs-region        = "us-east-1"
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])
}

resource "aws_ecs_task_definition" "backend_task" {
  family                   = "backend-task"
  requires_compatibilities = ["MANAGED_INSTANCES"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([
    {
      name      = "backend"
      image     = "${aws_ecr_repository.ecr-backend.repository_url}:latest"
      essential = true
      portMappings = [
        {
          containerPort = 8080
          protocol      = "tcp"
        }
      ]
      memory = 512
      cpu    = 256
      environment = [
        {
          name  = "DB_NAME"
          value = "todo"
        },
        {
          name  = "DB_USER"
          value = aws_db_instance.todo-db.username
        },
        {
          name  = "DB_PASS"
          value = aws_db_instance.todo-db.password
        },
        {
          name  = "DB_HOST"
          value = aws_db_instance.todo-db.address
        },
        {
          name = "FRONTEND_URL"
          value = "http://${aws_lb.todo-lb.dns_name}"
        }
      ]
    
      linuxParameters = {
        initProcessEnabled = true
      }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.backend_logs.name
          awslogs-region        = "us-east-1"
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])
}

# ----------------------------------
# ECS Services (use capacity provider strategy)
# ----------------------------------
resource "aws_ecs_service" "frontend_service" {
  name            = "frontend-service"
  cluster         = aws_ecs_cluster.todo-cluster.id
  task_definition = aws_ecs_task_definition.frontend_task.arn
  desired_count   = 1

  network_configuration {
    subnets          = [aws_subnet.todo-private[0].id, aws_subnet.todo-private[2].id]  # Spread across AZs for HA
    security_groups  = [aws_security_group.ecs-sg.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.frontend-tg.arn
    container_name   = "frontend"
    container_port   = 80
  }

  enable_execute_command = true

  capacity_provider_strategy {
    capacity_provider = aws_ecs_capacity_provider.todo_capacity_provider.name
    weight            = 1
    base              = 1
  }

  depends_on = [
    aws_lb_listener.frontend,
    aws_ecs_capacity_provider.todo_capacity_provider
  ]
}

resource "aws_ecs_service" "backend_service" {
  name            = "backend-service"
  cluster         = aws_ecs_cluster.todo-cluster.id
  task_definition = aws_ecs_task_definition.backend_task.arn
  desired_count   = 1

  network_configuration {
    subnets          = [aws_subnet.todo-private[0].id, aws_subnet.todo-private[2].id]  # Spread across AZs for HA
    security_groups  = [aws_security_group.ecs-sg.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.backend-tg.arn
    container_name   = "backend"
    container_port   = 8080
  }

  enable_execute_command = true

  capacity_provider_strategy {
    capacity_provider = aws_ecs_capacity_provider.todo_capacity_provider.name
    weight            = 1
    base              = 1
  }

  depends_on = [
    aws_lb_listener_rule.backend,
    aws_ecs_capacity_provider.todo_capacity_provider
  ]
}

